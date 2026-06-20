#!/usr/bin/env python3
"""Merge the trained LoRA adapter into the base and save a merged HF model,
so llama.cpp can convert it to GGUF (bypasses Unsloth's broken GGUF helper)."""
import glob, os
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
import torch

BASE = "/tmp/supra-base"
OUT = "/tmp/supra-merged"
ckpts = sorted(glob.glob("/home/nexland/AetherAV/tools/.train_out/checkpoint-*"),
               key=lambda p: int(p.rsplit("-", 1)[1]))
adapter = ckpts[-1]
print(">> base:", BASE, "| adapter:", adapter, flush=True)

tok = AutoTokenizer.from_pretrained(BASE)
model = AutoModelForCausalLM.from_pretrained(BASE, torch_dtype=torch.float16)
model = PeftModel.from_pretrained(model, adapter)
model = model.merge_and_unload()
os.makedirs(OUT, exist_ok=True)
model.save_pretrained(OUT, safe_serialization=True)
tok.save_pretrained(OUT)
print(">> merged model saved to", OUT, flush=True)
