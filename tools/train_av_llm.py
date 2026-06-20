#!/usr/bin/env python3
"""Fine-tune the compact (~50M) base into AetherAV's on-device detection engine.

Run with the Unsloth Studio venv python:
  /home/nexland/.unsloth/studio/unsloth_studio/bin/python tools/train_av_llm.py

Trains `usermma/Supra-50M-Reasoning-OBLITERATED` on our AV classifier dataset
(artifact -> "Verdict | MITRE | reason"), best-effort augmented with a real
HuggingFace malicious-PowerShell dataset, then exports a q4_k_m GGUF the engine
loads at assets/models/aegis-50m.gguf.
"""
import json, os, random, sys

ROOT = "/home/nexland/AetherAV"
OUT_GGUF_DIR = f"{ROOT}/assets/models/aether-llm"
BASE = "/tmp/supra-base"  # sanitized local copy (clean tokenizer_config for transformers 4.57)
MAXSEQ = 1024
EPOCHS = 3

from unsloth import FastLanguageModel
import torch
from datasets import load_dataset, Dataset
from trl import SFTTrainer, SFTConfig

print(">> loading base model", BASE, flush=True)
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=BASE, max_seq_length=MAXSEQ, dtype=None, load_in_4bit=False,
)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

# LoRA (fast). Fall back to full fine-tune if target modules don't match.
try:
    model = FastLanguageModel.get_peft_model(
        model, r=16, lora_alpha=16, lora_dropout=0.0, bias="none",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        use_gradient_checkpointing="unsloth", random_state=42,
    )
    print(">> LoRA adapters attached", flush=True)
except Exception as e:
    print(">> LoRA failed, full fine-tune:", e, flush=True)

EOS = tokenizer.eos_token or "</s>"

def to_text(instr, inp, out):
    return f"{instr}\n{inp}\n{out}{EOS}"

rows = []
# 1) our AV detector dataset (the core, exact inference format)
for line in open(f"{ROOT}/assets/datasets/av_train.jsonl"):
    r = json.loads(line)
    rows.append(to_text(r["instruction"], r["input"], r["output"]))
print(f">> our dataset: {len(rows)} examples", flush=True)

# Oversample benign PowerShell so the offensive-PS augmentation below can't
# teach "PowerShell == malicious" (was causing benign-PS false positives).
PS_TOK = ("Get-", "Write-Host", "Write-Output", "Import-Module", "Set-Location",
          "Test-Path", "Invoke-Pester", "New-Item", "Measure-Object", "Where-Object")
benign_ps = [r for r in rows if "Benign | - |" in r and any(t in r for t in PS_TOK)]
rows += benign_ps * 7
print(f">> oversampled benign PowerShell: +{len(benign_ps)*7}", flush=True)

# 2) best-effort HF augmentation: real offensive PowerShell -> malicious label
try:
    ds = load_dataset("dessertlab/offensive-PowerShell", split="train")
    col = next((c for c in ["code", "text", "powershell", "command", "prompt", "input"]
                if c in ds.column_names), None)
    if col:
        instr = "Classify this command line. Reply: verdict, MITRE technique (or -), one-line reason."
        n = 0
        for ex in ds.select(range(min(len(ds), 400))):  # capped so it can't dominate
            cmd = str(ex[col]).strip().replace("\n", " ")[:600]
            if len(cmd) < 6:
                continue
            rows.append(to_text(instr, cmd,
                "Malicious | T1059.001 | offensive PowerShell tradecraft"))
            n += 1
        print(f">> HF dessertlab/offensive-PowerShell: +{n} examples", flush=True)
    else:
        print(">> HF dataset columns unexpected, skipping:", ds.column_names, flush=True)
except Exception as e:
    print(">> HF augmentation skipped:", e, flush=True)

random.Random(42).shuffle(rows)
print(f">> total training examples: {len(rows)}", flush=True)
train_ds = Dataset.from_dict({"text": rows})

trainer = SFTTrainer(
    model=model, tokenizer=tokenizer, train_dataset=train_ds,
    args=SFTConfig(
        dataset_text_field="text", max_seq_length=MAXSEQ,
        per_device_train_batch_size=16, gradient_accumulation_steps=1,
        warmup_steps=20, num_train_epochs=EPOCHS, learning_rate=2e-4,
        logging_steps=25, optim="adamw_8bit", weight_decay=0.01,
        lr_scheduler_type="linear", seed=42,
        output_dir=f"{ROOT}/tools/.train_out", report_to="none",
    ),
)
print(">> training...", flush=True)
trainer.train()

# --- quick held-out eval ---
print(">> eval on av_eval.jsonl", flush=True)
FastLanguageModel.for_inference(model)
ev = [json.loads(l) for l in open(f"{ROOT}/assets/datasets/av_eval.jsonl")]
random.Random(1).shuffle(ev)
correct = 0; total = 0
for r in ev[:40]:
    prompt = f"{r['instruction']}\n{r['input']}\n"
    ids = tokenizer(prompt, return_tensors="pt").to("cuda")
    gen = model.generate(**ids, max_new_tokens=40, do_sample=False,
                         pad_token_id=tokenizer.pad_token_id)
    out = tokenizer.decode(gen[0][ids.input_ids.shape[1]:], skip_special_tokens=True)
    pred = out.strip().split("\n")[0].split("|")[0].strip().lower()
    gold = r["output"].split("|")[0].strip().lower()
    total += 1; correct += int(pred == gold)
    if total <= 8:
        print(f"   [{gold:>10}] pred={pred:>10}  in: {r['input'][:60]}", flush=True)
print(f">> verdict accuracy on {total} held-out: {100*correct/total:.1f}%", flush=True)

# --- export GGUF for the engine ---
print(">> exporting q4_k_m GGUF ->", OUT_GGUF_DIR, flush=True)
try:
    model.save_pretrained_gguf(OUT_GGUF_DIR, tokenizer, quantization_method="q4_k_m")
    # normalize the produced file name to assets/models/aegis-50m.gguf
    import glob, shutil
    g = sorted(glob.glob(f"{OUT_GGUF_DIR}/*.gguf"), key=os.path.getsize, reverse=True)
    if g:
        shutil.copy(g[0], f"{ROOT}/assets/models/aegis-50m.gguf")
        print(">> model ready:", f"{ROOT}/assets/models/aegis-50m.gguf",
              f"({os.path.getsize(g[0])//1024} KB)", flush=True)
except Exception as e:
    print(">> GGUF export failed:", e, flush=True)
print(">> DONE", flush=True)
