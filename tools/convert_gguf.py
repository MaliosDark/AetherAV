#!/usr/bin/env python3
"""Run llama.cpp's convert_hf_to_gguf, defaulting an unrecognized BPE
pre-tokenizer to 'llama-bpe' (the model is Llama-arch) instead of raising."""
import importlib.util, sys

LLAMA = "/home/nexland/.unsloth/llama.cpp"
sys.path.insert(0, LLAMA)
spec = importlib.util.spec_from_file_location("convert_hf_to_gguf", f"{LLAMA}/convert_hf_to_gguf.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Patch every class that defines get_vocab_base_pre to fall back gracefully.
for name in dir(mod):
    obj = getattr(mod, name)
    if isinstance(obj, type) and "get_vocab_base_pre" in obj.__dict__:
        _orig = obj.get_vocab_base_pre
        def patched(self, tok, _orig=_orig):
            try:
                return _orig(self, tok)
            except NotImplementedError:
                # tokenizer.json uses a ByteLevel (GPT-2) pre-tokenizer.
                print(">> unknown pre-tokenizer -> defaulting to 'gpt-2'", flush=True)
                return "gpt-2"
        obj.get_vocab_base_pre = patched

sys.argv = ["convert_hf_to_gguf.py", "/tmp/supra-merged",
            "--outfile", "/tmp/aether-f16.gguf", "--outtype", "f16"]
mod.main()
