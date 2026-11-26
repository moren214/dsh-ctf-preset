# Domain: Cryptography

- Built-in solver (`crypto_solver`):
  - Run `action: "solve"` directly for zero-dependency attacks on JWT HMAC secrets, Flask session cookies, LCG modulus/multiplier/increment recovery, and MT19937 state reconstruction.
  - Run `action: "check"` to inspect host `z3`/`fpylll`/`pycryptodome`/`sympy` availability and `sandbox_fallback`.
  - Generate starter scripts with `action: "template"` (`z3_bitvec`, `coppersmith`, `lattice`, `aes_mode`, `ecc_weak`, `padding_oracle`, `hash_ext`).
- Multi-step verification (`calculate_offline`): compute modular inverses, CRT, XOR, HMAC, AES, RSA, and hash chains with provenance hashes (`result_id`).
- Heavy math (`SageMath`, `fpylll` BKZ, complex LLL/Coppersmith): execute scripts via `ctf_sandbox(action: "exec", profile: "heavy")`.
