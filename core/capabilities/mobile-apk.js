import { createHash } from 'node:crypto';
import path from 'node:path';
import { ToolError } from '../contracts/errors.js';
import { parseZipEntries } from './zip-crack.js';

export function inspectApkInfo(buffer, tools) {
  const entries = parseZipEntries(buffer);
  const directoryEntries = entries.filter(entry => !entry.directory);
  const signingBlock = buffer.includes(Buffer.from('APK Sig Block 42', 'ascii'));
  const abis = [...new Set(entries.map(entry => /^lib\/([^/]+)\//u.exec(entry.name)?.[1]).filter(Boolean))];
  return {
    status: 'ok',
    input_sha256: createHash('sha256').update(buffer).digest('hex'),
    entries: directoryEntries.slice(0, 200).map(entry => ({ name: entry.name, size: entry.size })),
    entry_count: directoryEntries.length,
    has_manifest: entries.some(entry => entry.name === 'AndroidManifest.xml'),
    dex_files: entries.filter(entry => /^classes\d*\.dex$/u.test(entry.name)).map(entry => entry.name),
    dex_total_size: entries.filter(entry => /^classes\d*\.dex$/u.test(entry.name)).reduce((sum, entry) => sum + entry.size, 0),
    abis,
    native_libs: entries.filter(entry => entry.name.startsWith('lib/')).length,
    assets: entries.filter(entry => entry.name.startsWith('assets/')).length,
    signature_files: entries.filter(entry => /^META-INF\/.*\.(RSA|DSA|EC)$/iu.test(entry.name)).map(entry => entry.name),
    signing_block: signingBlock,
    tools,
    hint: '反编译用 action=decompile；签名校验用 action=signature。未安装工具时自动桥接沙箱或改用 shell。',
  };
}

export function buildSandboxApkDecompileScript() {
  return 'export HOME=/tmp/apk_home XDG_CONFIG_HOME=/tmp/apk_home/.config XDG_CACHE_HOME=/tmp/apk_home/.cache JAVA_TOOL_OPTIONS="-Duser.home=/tmp/apk_home"; '
    + 'mkdir -p "$HOME/.config" "$HOME/.cache"; '
    + 'if command -v jadx >/dev/null 2>&1; then echo "__TOOL=jadx"; exec jadx -d "$2" --no-res "$1"; '
    + 'elif command -v apktool >/dev/null 2>&1; then echo "__TOOL=apktool"; exec apktool d -f -o "$2" "$1"; '
    + 'else exit 127; fi';
}

export function buildSandboxApkSignatureScript() {
  return 'export HOME=/tmp/apk_home JAVA_TOOL_OPTIONS="-Duser.home=/tmp/apk_home"; mkdir -p "$HOME"; '
    + 'if command -v apksigner >/dev/null 2>&1; then echo "__TOOL=apksigner"; exec apksigner verify --print-certs "$1"; '
    + 'elif command -v jarsigner >/dev/null 2>&1; then echo "__TOOL=jarsigner"; exec jarsigner -verify -verbose -certs "$1"; '
    + 'elif command -v keytool >/dev/null 2>&1; then '
    + 'echo "__TOOL=keytool"; '
    + 'TMPD="$(mktemp -d /tmp/apksig_XXXXXX)"; trap \'rm -rf "$TMPD"\' EXIT; '
    + 'unzip -q -o "$1" "META-INF/*" -d "$TMPD" 2>/dev/null || true; '
    + 'CERT="$(find "$TMPD/META-INF" -maxdepth 1 -type f \\( -iname "*.RSA" -o -iname "*.DSA" -o -iname "*.EC" \\) | head -n 1)"; '
    + '[ -n "$CERT" ] || exit 127; exec keytool -printcert -file "$CERT"; '
    + 'else exit 127; fi';
}

export function defaultApkOutDir(filePath) {
  return '.apk-' + path.basename(filePath, path.extname(filePath));
}
