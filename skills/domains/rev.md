# Domain: Reverse Engineering

- Binary classification: inspect format, headers, sections, imports, and strings via `inspect_elf`, `rev_query(operation: "triage" / "strings" / "disassemble" / "cfg")`, and `scan_binary`.
- Decompilation pipeline:
  1. Start with `ctf_sandbox(action: "decompile")` omitting `function` to list functions + `image_base` + relative `offset`.
  2. Request targeted functions (or comma-separated batch up to 16 functions); `r2ghidra` returns in ~1s on `latest`, and `heavy` auto-caches Ghidra projects keyed by binary SHA-256.
- Obfuscation / Custom VM / Packing: inspect entropy/sections for UPX/packers, trace handlers with `gdb_driver` (`session_start`/`session_cmd`), and symbolically solve constraints with `angr`/`z3` inside `ctf_sandbox(profile: "heavy")`.
- Re-verify recovered constants and inverse transforms deterministically using `calculate_offline`.
