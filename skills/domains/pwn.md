# Domain: Binary Exploitation (Pwn)

- Local static triage first: run `inspect_elf` (NX/PIE/RELRO/Canary/imports/GOT/PLT) and `ctf_sandbox(action: "pwn_triage")` for `checksec`, libc hints, ROP gadgets, and `seccomp-tools`.
- Reversing vulnerability logic: `ctf_sandbox(action: "decompile")` (fast `r2ghidra` on `latest`, falling back to Ghidra 11.3.1 on `heavy` when needed).
- Cyclic offset & payload verification: compute De Bruijn offsets with `pwn_cyclic` and assemble bounds-checked x86-64 chains with `pwn_payload`.
- Dynamic debugging: use `gdb_driver` (`inspect`, `debug`, or persistent interactive `session_start`/`session_cmd`/`session_close` over ELF inside Docker `gdb-multiarch`).
- Live exploit interaction: use `net_session` (`connect`/`send`/`recv`/`read_until`) against `ctf_instance`-authorized TCP endpoints, or run pwntools scripts in `ctf_sandbox(action: "exec")` (`network: "bridge"` only with active authorization).
