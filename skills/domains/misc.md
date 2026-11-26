# Domain: Misc / Forensics / Stego

- Unknown containers & appended data: inspect headers with `inspect_attachment` / `scan_binary` / `read_binary_range` and extract nested entries with `read_archive_member` (`member_index`, `source_result_id`).
- ZIP recovery: check encryption metadata and brute-force ZipCrypto passwords via `archive_crack` (dictionary/mask/weak passwords) or use `bkcrack` in `ctf_sandbox`.
- Images / PDF / Office / SQLite / QR: run `inspect_media` first (`kind: "image"|"pdf"|"office"|"sqlite"|"qr"`) and `read_png_pixels` (`source_result_id`/`source_result_ids`) for exact pixel/LSB bitstreams.
- Audio (`WAV`): use `stego_audio` (`info`, `lsb`, `spectrum`) and chain extracted bytes via `source_result_id`.
- Network captures (`PCAP`/`PCAPNG`): use `pcap_stream` (IPv4 defrag, TCP stream reassembly, DNS queries/TXT, UTC time filter) or `tshark` inside `ctf_sandbox`.
