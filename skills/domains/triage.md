# Domain: Triage / Recon

- Start with `ctf_doctor(action: "check")` only if host capabilities or sandbox status are uncertain.
- Inspect unknown attachments with `inspect_attachment` and `scan_binary` before choosing heavyweight analyzers.
- For remote platforms, use `ctf_arena(challenges/detail/sync_graph/fetch_files)` to classify tasks by domain and download verified attachments into `.ctf-attachments/`.
- Record initial file hashes, detected formats (`ELF`, `PE`, `APK`, `PCAP`, `GGUF`, `ZIP`), and `classifyChallengeDomain` routing facts in `ctf_graph`, spawning typed child intents for specialized workers.
