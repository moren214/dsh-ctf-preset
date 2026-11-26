# Domain: AI / ML / LLM Security

- Static model inspection FIRST (never execute untrusted `.pkl`, `.pt`, `.pth`, `.ckpt`, or untrusted GGUF/Safetensors metadata before scanning):
  - Run `inspect_media(kind: "model")` to perform pure-static opcode & metadata inspection.
  - Pickle (Proto 0–5): flags dangerous globals (`os`, `subprocess`, `builtins.eval/exec`, `STACK_GLOBAL`, `REDUCE`, `NEWOBJ`, `BUILD`, `trailing_bytes`).
  - GGUF & Safetensors: decodes obfuscated Jinja2 `chat_template` / `__metadata__` SSTI payloads and checks `metadata_truncated` completeness.
  - PyTorch ZIP & ONNX: inspects member pickles, embedded code files, custom domains, and external tensor paths.
- LLM / Agent / RAG challenges: treat prompt injection, system-prompt leaks, tool-call SSRF, and jailbreaks strictly as black-box targets via `http_request` / `browser_session`; record confirmed prompt artifacts in `ctf_graph`.
