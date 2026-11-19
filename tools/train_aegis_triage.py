#!/usr/bin/env python3
"""Train a local Aegis triage candidate and compare held-out label scores."""

import argparse
import hashlib
import json
import random
from pathlib import Path

import torch
from gguf import GGUFReader
from safetensors.torch import save_file
from transformers import AutoModelForCausalLM, AutoTokenizer

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--base", type=Path, required=True, help="Local Aegis GGUF")
parser.add_argument("--train", type=Path, required=True)
parser.add_argument("--eval", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True, help="New directory for a candidate checkpoint")
parser.add_argument(
    "--incident-holdout",
    action="store_true",
    help="Require reviewed, disjoint incident groups and improvement before exporting",
)
args = parser.parse_args()
if args.out.exists():
    parser.error("--out must be a new candidate directory")
src = args.base.resolve()
torch.manual_seed(42)
torch.set_num_threads(2)
tok = AutoTokenizer.from_pretrained(src.parent, gguf_file=src.name, local_files_only=True)
model = AutoModelForCausalLM.from_pretrained(src.parent, gguf_file=src.name, local_files_only=True)
vocab = GGUFReader(src)
for key, token in (
    ("bos", "bos"), ("eos", "eos"), ("padding", "pad"), ("unknown", "unk")
):
    field = vocab.fields.get(f"tokenizer.ggml.{key}_token_id")
    if field is not None:
        setattr(tok, f"{token}_token", tok.convert_ids_to_tokens(field.contents()))
if tok.bos_token_id is None or tok.eos_token_id is None:
    parser.error("the GGUF must specify BOS and EOS tokens")
model.config.bos_token_id = model.generation_config.bos_token_id = tok.bos_token_id
model.config.eos_token_id = model.generation_config.eos_token_id = tok.eos_token_id
model.config.pad_token_id = model.generation_config.pad_token_id = tok.pad_token_id


def load_observations(path):
    observations = {}
    incidents = set()
    with path.open(encoding="utf-8") as data:
        for line in data:
            row = json.loads(line)
            if row["instruction"].startswith("Review these local behavioral observations"):
                if args.incident_holdout:
                    incident = row.get("incident_id")
                    if row.get("reviewed") is not True or not isinstance(incident, str) or not incident.strip():
                        raise ValueError("incident evaluation requires reviewed rows with incident_id")
                    incidents.add(incident)
                text = row["instruction"] + "\n" + row["input"] + "\n"
                reply = row["output"]
                if reply.split(" |", 1)[0] not in ("Benign", "Suspicious"):
                    raise ValueError("unexpected behavioral triage label")
                if text in observations and observations[text] != reply:
                    raise ValueError("one observation has conflicting expected replies")
                observations[text] = reply
    return observations, incidents


def prepared(prompt, response):
    prefix = [tok.bos_token_id] + tok.encode(prompt, add_special_tokens=False)
    continuation = tok.encode(response, add_special_tokens=False) + [tok.eos_token_id]
    if len(prefix) + len(continuation) > model.config.max_position_embeddings:
        raise ValueError("observation exceeds the model context window")
    ids = torch.tensor([prefix + continuation])
    response_logits = torch.arange(len(prefix) - 1, ids.size(1) - 1)
    return ids, response_logits


def response_loss(prompt, response):
    ids, positions = prepared(prompt, response)
    logits = model(input_ids=ids, logits_to_keep=positions, use_cache=False).logits
    return torch.nn.functional.cross_entropy(logits[0], ids[0, positions + 1])


@torch.inference_mode()
def evaluate(examples):
    model.eval()
    correct = fp = fn = 0
    loss = 0
    labels = ("Benign", "Suspicious")
    for prompt, reply in examples:
        loss += float(response_loss(prompt, reply))
        predicted = min(labels, key=lambda label: float(response_loss(prompt, label + " |")))
        expected = reply.split(" |", 1)[0]
        correct += predicted == expected
        fp += predicted == "Suspicious" and expected == "Benign"
        fn += predicted == "Benign" and expected == "Suspicious"
    return {
        "rows": len(examples), "correct": correct, "fp": fp, "fn": fn,
        "mean_response_loss": loss / len(examples),
    }


train, train_incidents = load_observations(args.train)
test, test_incidents = load_observations(args.eval)
if train_incidents & test_incidents:
    raise ValueError("incident groups overlap training and evaluation")
if train.keys() & test.keys():
    raise ValueError("train and evaluation observations overlap")
if len({reply.split(" |", 1)[0] for reply in test.values()}) != 2:
    raise ValueError("evaluation requires both labels")
rng = random.Random(42)
examples = []
for label in ("Benign", "Suspicious"):
    labelled = [(prompt, reply) for prompt, reply in train.items() if reply.startswith(label + " |")]
    rng.shuffle(labelled)
    if len(labelled) < 128:
        raise ValueError(f"at least 128 distinct {label} observations required")
    examples.extend(labelled[:128])
rng.shuffle(examples)
test = list(test.items())
baseline = evaluate(test)
print(json.dumps({"baseline": baseline, "train_rows": len(examples)}), flush=True)
model.requires_grad_(False)
for layer in model.model.layers[-2:]:
    layer.requires_grad_(True)
model.model.norm.requires_grad_(True)
params = [p for p in model.parameters() if p.requires_grad]
optimizer = torch.optim.AdamW(params, lr=8e-5, weight_decay=0.01)
model.train()
optimizer.zero_grad(set_to_none=True)
for index, (prompt, reply) in enumerate(examples, 1):
    loss = response_loss(prompt, reply)
    (loss / 4).backward()
    if index % 4 == 0:
        torch.nn.utils.clip_grad_norm_(params, 1.0)
        optimizer.step()
        optimizer.zero_grad(set_to_none=True)
    if index % 64 == 0:
        print(f"examples={index} last_loss={loss.item():.4f}", flush=True)
candidate = evaluate(test)
gate_passed = candidate["fp"] <= baseline["fp"] and candidate["fn"] < baseline["fn"]
print(json.dumps({
    "candidate": candidate,
    "trainable_params": sum(p.numel() for p in params),
    "incident_gate": ("pass" if gate_passed else "fail") if args.incident_holdout else "disabled",
}), flush=True)
if args.incident_holdout and not gate_passed:
    parser.exit(3, "candidate must reduce missed incidents without increasing false positives\n")
args.out.mkdir()
# The experimental artifact contains only the trained layers. Loading it
# requires the same base checkpoint. This avoids writing the frozen weights.
with src.open("rb") as base:
    base_sha = hashlib.file_digest(base, "sha256").hexdigest()
save_file(
    {name: parameter.detach().contiguous() for name, parameter in model.named_parameters()
     if parameter.requires_grad},
    args.out / "aegis-triage-layers.safetensors",
    metadata={"base_gguf_sha256": base_sha},
)
