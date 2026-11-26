# Domain: Mobile / Android (APK/DEX)

- Structural triage first: run `mobile_apk(action: "info")` to inspect `AndroidManifest.xml`, `classes*.dex`, native `.so` ABIs, assets, and signing blocks/certificates.
- Certificate verification: run `mobile_apk(action: "signature")` (automatically bridges to `apksigner`/`jarsigner`/`keytool` inside `dsh-ctf-sandbox:heavy` when missing on host).
- Decompilation: run `mobile_apk(action: "decompile")` (bridges to `jadx --no-res` / `apktool` on `heavy` with writable `/tmp` JVM caches compatible with `--read-only`).
- Native `.so` libraries (`lib/<abi>/*.so`): analyze extracted JNI binaries with `inspect_elf`, `rev_query`, or `ctf_sandbox(action: "decompile")`.
