# Training the on-device LLM detection engine

Goal: a **compact (~50M) model that runs everywhere (CPU)** and acts as a
*detection engine*, not a chatbot. It reads an artifact (a command line, a
script, a behavior summary) and emits one parseable line:

```
Malicious | T1059.001 | encoded PowerShell download-execute cradle
```

The engine (`aether-llm`) prompts the model and parses that line into a
`Verdict` (engine = `Llm`), fused with the other engines in the scan pipeline.

## 1. Dataset

Generate the AV classifier dataset (regenerate any time to refresh patterns):

```bash
python3 tools/gen_av_dataset.py --n 6000 --format alpaca \
    --out assets/datasets/av_train.jsonl --eval assets/datasets/av_eval.jsonl
# -> 5400 train + 600 eval, Alpaca {instruction,input,output}
```

Every record is `artifact -> "Verdict | MITRE | reason"`. Add your own real
samples (one JSONL line each) - that's where the biggest accuracy gains are.

## 2. Fine-tune (Unsloth / QLoRA)

Your 50M run was only **0.09 epoch** - a smoke test. For a focused classifier
the model needs many passes over this small, narrow set:

| setting | value | why |
|---|---|---|
| epochs | **3-8** (not 0.09) | 50M needs many passes on a small task |
| max_seq_len | 256-512 | inputs/outputs are short -> faster, cheaper |
| lora_r / alpha | 16 / 32 | enough capacity for a narrow task |
| learning_rate | 2e-4 | standard QLoRA |
| batch (eff.) | 16-32 | stable gradients |
| objective | **train on the response only** | learn the label, not the prompt |
| watch | **eval loss** on `av_eval.jsonl` | stop when it stops improving |

Keep the **same prompt template** the engine uses (the `instruction` field
above). Train on the assistant/response span only so it learns the verdict.

## 3. Export to GGUF (runs anywhere)

```python
# in your Unsloth script, after training:
model.save_pretrained_gguf("aether-llm", tokenizer, quantization_method="q4_k_m")
```

`q4_k_m` keeps a 50M model around ~30-40 MB - CPU-friendly on any device.
Place it where the engine looks:

```bash
cp aether-llm/*.gguf assets/models/aegis-50m.gguf
```

## 4. Enable the engine

```toml
# aether.toml
[engines]
llm = true
llm_runner = "llama-cli"     # llama.cpp; must be on PATH
llm_model  = "assets/models/aegis-50m.gguf"
```

Now `aether scan` runs the model on script/command artifacts and folds its
verdict in with hash/YARA/heuristics/ML/sandbox/intel. With no model present
the engine is inert (zero impact) - so the build always works everywhere, and
the model is a drop-in upgrade.

## 5. Validate

Use the labeled eval split and the engine's own evaluator:

```bash
# compare model verdicts vs labels (your own harness over av_eval.jsonl), and
aether eval --clean <benign-scripts> --malware <malicious-scripts>
```

Track detection rate + false-positive rate; a tiny model is only worth shipping
if FPR stays low on benign scripts.
