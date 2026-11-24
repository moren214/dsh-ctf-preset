import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { open } from 'node:fs/promises';
import path from 'node:path';
import { describeToolError, ToolError } from './tool-errors.js';

const DEFAULT_IMAGE = 'dsh-ctf-sandbox:latest';
const DEFAULT_HEAVY_IMAGE = 'dsh-ctf-sandbox:heavy';
const DEFAULT_TIMEOUT_MS = 30000;
const HEAVY_DECOMPILE_TIMEOUT_MS = 120000;
const MIN_TIMEOUT_MS = 1000;
const MAX_TIMEOUT_MS = 180000;
const MAX_OUTPUT_BYTES = 64 * 1024;
const MAX_COMMAND_CHARS = 4096;
const SCRIPT_PREVIEW_BYTES = 8192;
const DETECT_CACHE_TTL_MS = 30000;
const FULL_ARSENAL_PATTERN = /\b(?:ROPgadget|ropper|seccomp-tools|one_gadget|pwntools|pwn|pwninit|z3|sympy|gmpy2|fpylll|capstone|angr|sage|sagemath|binwalk|steghide|tshark|radare2|r2|rizin|analyzeHeadless|ghidra|jadx|apktool|Crypto|upx|gdb-multiarch|qemu-[a-z0-9_]+|zsteg|exiftool|pngcheck|zbarimg|sox|ffmpeg|vol3?|volatility3|php|socat|wasm2wat|wasm-objdump|wasm-decompile|fls|icat|mmls|cpio|scapy|scipy|xdis|bkcrack|ffuf|sqlmap|john|tesseract|pyinstxtractor)\b/u;
const HEAVY_ARSENAL_PATTERN = /\b(?:analyzeHeadless|ghidra|angr|jadx|apktool|sage|sagemath)\b/u;
const HEAVY_SCRIPT_IMPORT_PATTERN = /(?:^|\r?\n)\s*(?:import\s+(?:angr|cle|claripy|pyvex|archinfo|sage)\b|from\s+(?:angr|cle|claripy|pyvex|archinfo|sage)(?:\.|\s)|\b(?:analyzeHeadless|jadx|apktool)\b)/u;
const APK_WORKLOAD_PATTERN = /\.(?:apk|dex|smali|aab)(?:["'\s]|$)/iu;
const detectCache = new Map();

export const SANDBOX_PROPERTIES = {
  action: {
    type: 'string',
    enum: ['status', 'exec', 'decompile', 'pwn_triage'],
    description: 'status 探测沙箱；exec 跑命令/脚本；decompile 列出函数或反编译；pwn_triage 采集 checksec/libc/gadget/seccomp。',
  },
  backend: { type: 'string', enum: ['auto', 'docker', 'wsl'], description: '单次覆盖后端；要求隔离时选 docker。auto 不会将隔离任务静默降级到 WSL。' },
  profile: { type: 'string', enum: ['auto', 'base', 'heavy'], description: '镜像档位：auto 自动按需升级重型镜像；base 轻量全栈；heavy 重器（Ghidra/angr/jadx/Sage，自动扩容 4g 内存）。' },
  command: { type: 'string', maxLength: MAX_COMMAND_CHARS, description: 'exec 单行命令。' },
  script_path: { type: 'string', maxLength: 1024, description: 'exec 工作区脚本路径（.py/.sh/.sage）。' },
  file_path: { type: 'string', maxLength: 1024, description: 'decompile/pwn_triage 目标二进制相对路径。' },
  function: { type: 'string', maxLength: 256, description: 'decompile 函数名或 0x 地址；省略列函数表。' },
  network: { type: 'string', enum: ['none', 'bridge'], default: 'none' },
  ptrace: { type: 'boolean', default: false },
  read_only_work: { type: 'boolean', default: false, description: 'Docker 后端以只读方式挂载 /work（跑陌生程序防篡改工作区）。' },
  allow_exec: { type: 'boolean', default: false, description: 'pwn_triage 是否运行 seccomp-tools dump。' },
  timeout_ms: { type: 'integer', minimum: MIN_TIMEOUT_MS, maximum: MAX_TIMEOUT_MS, default: DEFAULT_TIMEOUT_MS },
};

export function clearSandboxCache() {
  detectCache.clear();
}

export function resolveConfiguredImages(config = {}) {
  const rawBase = typeof config?.sandboxImage === 'string' && config.sandboxImage.trim() !== ''
    ? config.sandboxImage.trim() : undefined;
  const rawHeavy = typeof config?.sandboxHeavyImage === 'string' && config.sandboxHeavyImage.trim() !== ''
    ? config.sandboxHeavyImage.trim() : undefined;
  const baseImage = rawBase ?? DEFAULT_IMAGE;
  const heavyImage = rawHeavy
    ?? (!rawBase || rawBase === DEFAULT_IMAGE
      ? DEFAULT_HEAVY_IMAGE
      : /:latest$/u.test(rawBase) ? rawBase.replace(/:latest$/u, ':heavy') : baseImage);
  return { baseImage, heavyImage };
}

export function analyzeSandboxNeed(args = {}, { scriptPreview } = {}) {
  const reasons = [];
  const heavyReasons = [];
  if (args.backend === 'docker') reasons.push('explicit_docker');
  if (args.profile === 'heavy') heavyReasons.push('explicit_heavy');
  if (args.action === 'pwn_triage') reasons.push('pwn_triage_arsenal');
  if (args.action === 'decompile') reasons.push('decompile_arsenal');
  if (args.ptrace === true) reasons.push('ptrace_isolation');
  if (args.action === 'exec') {
    if (typeof args.command === 'string') {
      if (FULL_ARSENAL_PATTERN.test(args.command)) reasons.push('arsenal_command');
      if (HEAVY_ARSENAL_PATTERN.test(args.command)) heavyReasons.push('heavy_command');
      if (APK_WORKLOAD_PATTERN.test(args.command)) heavyReasons.push('apk_workload');
    }
    if (typeof args.script_path === 'string' && args.script_path.trim() !== '') {
      const trimmed = args.script_path.trim();
      if (/\.sage$/iu.test(trimmed)) heavyReasons.push('sage_script');
      else if (/\.py$/iu.test(trimmed)) reasons.push('python_script_arsenal');
      else if (!/\.sh$/iu.test(trimmed)) reasons.push('binary_isolation');
    }
    if (typeof scriptPreview === 'string' && HEAVY_SCRIPT_IMPORT_PATTERN.test(scriptPreview)) {
      heavyReasons.push('heavy_script_import');
    }
  }
  if (heavyReasons.length > 0 && !reasons.includes('heavy_arsenal')) {
    reasons.push('heavy_arsenal');
  }
  return {
    preferDocker: reasons.length > 0,
    preferHeavy: heavyReasons.length > 0,
    reasons,
    heavyReasons,
  };
}

export function resolveExecutionPlan(detected, need = {}, requestedProfile = 'auto') {
  const wantsHeavy = requestedProfile === 'heavy' || (requestedProfile === 'auto' && Boolean(need.preferHeavy));
  if (detected?.backend !== 'docker') {
    const heavyImage = detected?.docker?.heavy?.image ?? DEFAULT_HEAVY_IMAGE;
    return {
      backend: detected?.backend ?? 'unavailable',
      profile: detected?.backend === 'wsl' ? 'wsl' : 'unavailable',
      image: undefined,
      autoUpgraded: false,
      upgradeReasons: [],
      ...(wantsHeavy && detected?.backend === 'wsl' ? {
        profileFallbackReason: `当前任务适合重型镜像 ${heavyImage}（${(need.heavyReasons?.length ? need.heavyReasons : ['explicit_heavy']).join(', ')}），但 Docker 暂不可用，已自动回退 WSL2。`,
      } : {}),
    };
  }
  const base = detected.docker?.base ?? { image: detected.image ?? DEFAULT_IMAGE, available: Boolean(detected.image) };
  const heavy = detected.docker?.heavy ?? { image: base.image, available: false };
  if (wantsHeavy) {
    if (heavy.available) {
      return {
        backend: 'docker',
        profile: 'heavy',
        image: heavy.image,
        autoUpgraded: requestedProfile === 'auto',
        upgradeReasons: requestedProfile === 'auto' ? [...(need.heavyReasons ?? [])] : ['explicit_heavy'],
      };
    }
    return {
      backend: 'docker',
      profile: /:heavy$/iu.test(base.image) ? 'heavy' : 'base',
      image: base.image,
      autoUpgraded: false,
      upgradeReasons: [],
      profileFallbackReason: `未检测到重型镜像 ${heavy.image}，已自动回退至 ${base.image}；如需 Ghidra/angr/jadx/Sage 可先构建：docker build -f docker/Dockerfile.heavy -t ${heavy.image} docker/`,
    };
  }
  if (base.available) {
    return {
      backend: 'docker',
      profile: /:heavy$/iu.test(base.image) ? 'heavy' : 'base',
      image: base.image,
      autoUpgraded: false,
      upgradeReasons: [],
    };
  }
  return {
    backend: 'docker',
    profile: 'heavy',
    image: heavy.image,
    autoUpgraded: true,
    upgradeReasons: ['heavy_only_available'],
  };
}

function truncateText(text, limit = MAX_OUTPUT_BYTES) {
  const value = String(text ?? '');
  if (value.length <= limit) return { text: value, truncated: false };
  return { text: `${value.slice(0, limit)}\n…（输出已截断，共 ${value.length} 字符）`, truncated: true };
}

export function parseWslList(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return [];
  const hasNull = buffer.includes(0);
  const text = buffer.toString(hasNull ? 'utf16le' : 'utf8').replace(/^\uFEFF/u, '');
  return text.split(/\r?\n/u)
    .map(line => line.replace(/\0/gu, '').trim())
    .filter(Boolean);
}

export function chooseWslDistro(distros, configured) {
  if (typeof configured === 'string' && configured.trim() !== '') {
    const wanted = configured.trim();
    return distros.find(item => item.toLowerCase() === wanted.toLowerCase()) ?? wanted;
  }
  return distros.find(name => !/^docker-desktop(?:$|[-_])/iu.test(name));
}

function runProcess(command, args, { cwd, timeoutMs = DEFAULT_TIMEOUT_MS, signal, maxBytes = MAX_OUTPUT_BYTES, onKill } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason ?? new ToolError('abort', '沙箱调用已取消。'));
    let child;
    try {
      child = spawn(command, args, {
        cwd,
        windowsHide: true,
        ...(process.platform !== 'win32' ? { detached: true } : {}),
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      return reject(error);
    }
    const outChunks = [];
    const errChunks = [];
    let outLen = 0;
    let errLen = 0;
    let outTruncated = false;
    let errTruncated = false;
    let timedOut = false;
    let aborted = false;
    let settled = false;

    const killChild = () => {
      try { onKill?.(); } catch { /* best-effort container kill */ }
      if (child.pid) {
        if (process.platform === 'win32') {
          const taskkill = process.env.SystemRoot ? path.join(process.env.SystemRoot, 'System32', 'taskkill.exe') : 'taskkill';
          try {
            const killer = spawn(taskkill, ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
            killer.on('error', () => {});
            killer.unref();
          } catch { /* fallback */ }
        } else {
          try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already exited */ }
        }
      }
      try { child.kill('SIGKILL'); } catch { /* already exited */ }
    };

    const onAbort = () => {
      if (settled) return;
      aborted = true;
      killChild();
    };
    const timer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      killChild();
    }, timeoutMs);
    if (signal) {
      signal.addEventListener('abort', onAbort, { once: true });
      if (signal.aborted) onAbort();
    }

    child.stdout?.on('data', chunk => {
      if (outLen >= maxBytes) { outTruncated = true; return; }
      const keep = chunk.subarray(0, maxBytes - outLen);
      outChunks.push(keep);
      outLen += keep.length;
      if (keep.length < chunk.length) outTruncated = true;
    });
    child.stderr?.on('data', chunk => {
      if (errLen >= maxBytes) { errTruncated = true; return; }
      const keep = chunk.subarray(0, maxBytes - errLen);
      errChunks.push(keep);
      errLen += keep.length;
      if (keep.length < chunk.length) errTruncated = true;
    });
    child.on('error', error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      reject(aborted ? (signal?.reason ?? new ToolError('abort', '沙箱调用已取消。')) : error);
    });
    child.on('close', code => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      if (aborted) return reject(signal?.reason ?? new ToolError('abort', '沙箱调用已取消。'));
      resolve({
        code: code ?? -1,
        stdoutBuf: Buffer.concat(outChunks, outLen),
        stderrBuf: Buffer.concat(errChunks, errLen),
        stdout: Buffer.concat(outChunks, outLen).toString('utf8'),
        stderr: Buffer.concat(errChunks, errLen).toString('utf8'),
        stdoutTruncated: outTruncated,
        stderrTruncated: errTruncated,
        timedOut,
      });
    });
  });
}

async function inspectDockerImage(image, signal) {
  const inspect = await runProcess('docker', ['image', 'inspect', '--format', '{{.Id}}', image], { timeoutMs: 3500, signal, maxBytes: 4096 });
  return !inspect.timedOut && inspect.code === 0;
}

async function probeDocker(baseImage, heavyImage, signal) {
  const emptyBase = { image: baseImage, available: false };
  const emptyHeavy = { image: heavyImage, available: false };
  try {
    const info = await runProcess('docker', ['info', '--format', '{{.ServerVersion}}'], { timeoutMs: 3500, signal, maxBytes: 4096 });
    if (info.timedOut || info.code !== 0) {
      return { available: false, reason: 'Docker daemon 未运行或不可访问。', base: emptyBase, heavy: emptyHeavy };
    }
    const daemonVersion = info.stdout.trim();
    const [baseAvailable, heavyAvailable] = heavyImage === baseImage
      ? await inspectDockerImage(baseImage, signal).then(ok => [ok, ok])
      : await Promise.all([inspectDockerImage(baseImage, signal), inspectDockerImage(heavyImage, signal)]);
    const base = { image: baseImage, available: baseAvailable };
    const heavy = { image: heavyImage, available: heavyAvailable };
    if (!baseAvailable && !heavyAvailable) {
      return {
        available: false,
        daemon_version: daemonVersion,
        base,
        heavy,
        reason: `未找到镜像 ${baseImage}${heavyImage !== baseImage ? ` 或 ${heavyImage}` : ''}（可用 docker build -t ${baseImage} docker/ 构建）。`,
      };
    }
    return {
      available: true,
      backend: 'docker',
      image: baseAvailable ? baseImage : heavyImage,
      daemon_version: daemonVersion,
      base,
      heavy,
    };
  } catch (error) {
    if (signal?.aborted) throw error;
    return { available: false, reason: '未检测到本机 docker 命令。', base: emptyBase, heavy: emptyHeavy };
  }
}

async function probeWsl(configuredDistro, signal) {
  if (process.platform !== 'win32') return { available: false, reason: '当前非 Windows 平台，不适用 WSL2。' };
  try {
    const list = await runProcess('wsl.exe', ['-l', '-q'], { timeoutMs: 4000, signal, maxBytes: 16384 });
    if (list.timedOut || list.code !== 0) return { available: false, reason: 'WSL2 查询失败或未启用。' };
    const distros = parseWslList(list.stdoutBuf);
    const chosen = chooseWslDistro(distros, configuredDistro);
    if (!chosen || (distros.length > 0 && !distros.some(d => d.toLowerCase() === chosen.toLowerCase()))) {
      return { available: false, distros, reason: configuredDistro ? `未找到 WSL 发行版 ${configuredDistro}。` : '未检测到可用的 Linux WSL 发行版。' };
    }
    return { available: true, backend: 'wsl', distro: chosen, distros };
  } catch (error) {
    if (signal?.aborted) throw error;
    return { available: false, reason: '未检测到本机 wsl.exe。' };
  }
}

export async function detectSandbox(config = {}, signal, { fresh = false } = {}) {
  const preference = ['auto', 'docker', 'wsl'].includes(config?.sandboxBackend) ? config.sandboxBackend : 'auto';
  const { baseImage, heavyImage } = resolveConfiguredImages(config);
  const wslDistro = typeof config?.sandboxWslDistro === 'string' && config.sandboxWslDistro.trim() !== ''
    ? config.sandboxWslDistro.trim() : undefined;

  const cacheKey = `${preference}|${baseImage}|${heavyImage}|${wslDistro ?? ''}`;
  if (!fresh) {
    const cached = detectCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
      return { ...cached.value, cached: true };
    }
  }

  let docker = {
    available: false,
    reason: '按配置跳过 Docker 探测。',
    base: { image: baseImage, available: false },
    heavy: { image: heavyImage, available: false },
  };
  let wsl = { available: false, reason: '按配置跳过 WSL 探测。' };
  if (preference === 'docker' || preference === 'auto') {
    docker = await probeDocker(baseImage, heavyImage, signal);
  }
  if (preference === 'wsl' || (preference === 'auto' && !docker.available)) {
    wsl = await probeWsl(wslDistro, signal);
  }
  const active = preference === 'docker' ? (docker.available ? docker : undefined)
    : preference === 'wsl' ? (wsl.available ? wsl : undefined)
      : (docker.available ? docker : wsl.available ? wsl : undefined);
  const value = {
    available: Boolean(active),
    preference,
    backend: active?.backend ?? 'unavailable',
    ...(active?.image ? { image: active.image } : {}),
    ...(active?.distro ? { distro: active.distro } : {}),
    profiles: { base: docker.base, heavy: docker.heavy },
    docker,
    wsl,
  };
  if (!signal?.aborted) {
    if (detectCache.size >= 16) detectCache.clear();
    detectCache.set(cacheKey, { value, expiresAt: Date.now() + DETECT_CACHE_TTL_MS });
  }
  return value;
}

export function buildDockerArgs(argv, { cwd, containerName, targetImage, isHeavy = false, network = 'none', ptrace = false, readOnlyWork = false }) {
  return [
    'run', '--rm', '--init', '--name', containerName,
    '--read-only',
    '--tmpfs', '/tmp:rw,nosuid,size=512m',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges:true',
    `--pids-limit=${isHeavy ? 512 : 256}`,
    `--memory=${isHeavy ? '4g' : '2g'}`,
    `--memory-swap=${isHeavy ? '4g' : '2g'}`,
    '--cpus=2',
    '--network', network === 'bridge' ? 'bridge' : 'none',
    ...(ptrace ? ['--cap-add=SYS_PTRACE'] : []),
    '-v', `${cwd}:/work${readOnlyWork ? ':ro' : ''}`,
    '-w', '/work',
    targetImage,
    ...argv,
  ];
}

export async function runSandboxCommand(argv, { cwd, config = {}, signal, timeoutMs = DEFAULT_TIMEOUT_MS, network = 'none', ptrace = false, readOnlyWork = false, requiresIsolation = false, detected, image, profile = 'base' } = {}) {
  const env = detected ?? await detectSandbox(config, signal);
  if (!env.available) {
    throw new ToolError('dependency',
      `Linux 沙箱不可用（Docker: ${env.docker.reason}；WSL2: ${env.wsl.reason}）。请构建 ${config?.sandboxImage ?? DEFAULT_IMAGE} 或启用 WSL2 Ubuntu。`);
  }
  if (requiresIsolation && env.backend !== 'docker' && env.preference === 'auto') {
    throw new ToolError('dependency',
      'Docker 不可用，auto 后端只能使用共享宿主网络和权限的 WSL2，无法满足此任务的隔离要求。请启动 Docker 并构建沙箱镜像；如仍要在 WSL2 中运行，请显式设置 backend: "wsl"。');
  }
  const started = Date.now();
  if (env.backend === 'docker') {
    const targetImage = image ?? env.image;
    const isHeavy = profile === 'heavy' || /:heavy$/iu.test(targetImage ?? '');
    const containerName = 'dsh-ctf-' + randomUUID().slice(0, 12);
    const dockerArgs = buildDockerArgs(argv, { cwd, containerName, targetImage, isHeavy, network, ptrace, readOnlyWork });
    const result = await runProcess('docker', dockerArgs, {
      timeoutMs, signal,
      onKill() {
        const killer = spawn('docker', ['kill', containerName], { windowsHide: true, stdio: 'ignore' });
        killer.on('error', () => {});
        killer.unref();
      },
    });
    return { ...result, backend: 'docker', target: targetImage, profile: isHeavy ? 'heavy' : 'base', elapsed_ms: Date.now() - started };
  }
  const wslArgs = ['-d', env.distro, '--cd', cwd, '--exec', ...argv];
  const result = await runProcess('wsl.exe', wslArgs, { timeoutMs, signal });
  return { ...result, backend: 'wsl', target: env.distro, profile: 'wsl', elapsed_ms: Date.now() - started };
}

const PROBE_SCRIPT = [
  'import importlib.util, json, os, shutil, platform',
  'bins = ["gdb","gdb-multiarch","objdump","readelf","nm","file","strings","checksec","patchelf","pwninit","upx","strace","ltrace","qemu-i386","qemu-arm","qemu-aarch64","qemu-riscv64","seccomp-tools","ROPgadget","ropper","one_gadget","r2","radare2","rizin","analyzeHeadless","tshark","binwalk","steghide","zsteg","exiftool","pngcheck","zbarimg","sox","ffmpeg","7z","cpio","wasm2wat","wasm-objdump","fls","icat","mmls","sqlite3","jq","xxd","php","node","socat","vol","vol3","jadx","apktool","bkcrack","ffuf","sqlmap","john","tesseract","python3","sage"]',
  'mods = ["pwn","capstone","z3","Crypto","sympy","gmpy2","angr","fpylll","ecdsa","jwt","itsdangerous","requests","bs4","flask","volatility3","ropper","PIL","numpy","scipy","scapy","xdis"]',
  'ghidra = shutil.which("analyzeHeadless") or (os.path.join(os.environ.get("GHIDRA_HOME",""),"support","analyzeHeadless") if os.environ.get("GHIDRA_HOME") else "")',
  'tools = {b: shutil.which(b) is not None for b in bins}',
  'if ghidra and os.path.isfile(ghidra): tools["analyzeHeadless"] = True',
  'gdb_plugins = {"gef": any(os.path.isfile(p) for p in ["/opt/gef/gef.py", os.path.expanduser("~/.gdbinit-gef.py")]), "pwndbg": os.path.isdir("/opt/pwndbg")}',
  'print(json.dumps({"system": platform.platform(), "arch": platform.machine(), "tools": tools, "python_modules": {m: importlib.util.find_spec(m) is not None for m in mods}, "gdb_plugins": gdb_plugins}))',
].join('\n');

export const DECOMPILE_SCRIPT = String.raw`
import hashlib, json, os, re, shutil, struct, subprocess, sys, tempfile

binary = sys.argv[1]
target = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
prefer_engine = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else "auto"
headless_timeout = max(1, int(sys.argv[4]) // 1000 - 2) if len(sys.argv) > 4 else 88
r2 = shutil.which("r2") or shutil.which("radare2") or shutil.which("rizin")
ghidra = shutil.which("analyzeHeadless")
if not ghidra and os.environ.get("GHIDRA_HOME"):
    cand = os.path.join(os.environ["GHIDRA_HOME"], "support", "analyzeHeadless")
    if os.path.isfile(cand):
        ghidra = cand
ghidra_diagnostic = None

def run(cmd, timeout=45):
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr

def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def parse_r2_sections(output):
    markers = ("__DSH_R2_PDG__", "__DSH_R2_PDC__", "__DSH_R2_ASM__")
    sections = {m: [] for m in markers}
    current = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped in sections:
            current = stripped
            continue
        if current is not None:
            sections[current].append(line)
    return {k: "\n".join(v).strip() for k, v in sections.items()}

def clean_r2_pseudo(text):
    if not text:
        return ""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""
    if len(lines) <= 3 and any(
        line.startswith(("Cannot find", "Invalid command", "Unknown command", "ERROR:"))
        for line in lines
    ):
        return ""
    return text

def decompile_ghidra(ghidra_bin, bin_path, func_target):
    global ghidra_diagnostic
    script_dir = tempfile.mkdtemp(prefix="dsh_ghidra_script_")
    script_path = os.path.join(script_dir, "DshDecomp.py")
    out_path = os.path.join(script_dir, "out.json")
    py_script = (
        "# -*- coding: utf-8 -*-\n"
        "from __future__ import unicode_literals\n"
        "import json, os\n"
        "from ghidra.app.decompiler import DecompInterface\n"
        "def norm_addr(raw):\n"
        "    s = str(raw).strip().lower()\n"
        "    if s.startswith('0x'): s = s[2:]\n"
        "    if not s or any(ch not in '0123456789abcdef' for ch in s): return None\n"
        "    return '0x' + (s.lstrip('0') or '0')\n"
        "target = os.environ.get('DSH_TARGET') or None\n"
        "prog_name = currentProgram.getName()\n"
        "img_base = int(currentProgram.getImageBase().getOffset())\n"
        "img_base_hex = hex(img_base).rstrip('L')\n"
        "fm = currentProgram.getFunctionManager()\n"
        "if not target:\n"
        "    funcs = []\n"
        "    for f in fm.getFunctions(True):\n"
        "        entry_off = int(f.getEntryPoint().getOffset())\n"
        "        entry_norm = norm_addr(f.getEntryPoint().toString()) or ('0x' + f.getEntryPoint().toString())\n"
        "        item = {'name': f.getName(), 'address': entry_norm, 'size': int(f.getBody().getNumAddresses())}\n"
        "        if img_base > 0 and entry_off >= img_base:\n"
        "            item['offset'] = hex(entry_off - img_base).rstrip('L')\n"
        "        funcs.append(item)\n"
        "        if len(funcs) >= 200: break\n"
        "    res = {'engine': 'ghidra', 'mode': 'list', 'program_name': prog_name, 'image_base': img_base_hex, 'function_count': len(funcs), 'functions': funcs}\n"
        "    if not funcs: res['warning'] = 'Ghidra 没有识别到函数。'\n"
        "else:\n"
        "    target_norm = norm_addr(target)\n"
        "    hit = None\n"
        "    for f in fm.getFunctions(True):\n"
        "        entry_off = int(f.getEntryPoint().getOffset())\n"
        "        addr_s = norm_addr(f.getEntryPoint().toString())\n"
        "        rel_s = norm_addr(hex(entry_off - img_base).rstrip('L')) if (img_base > 0 and entry_off >= img_base) else None\n"
        "        if f.getName() == target or (target_norm is not None and (addr_s == target_norm or rel_s == target_norm)):\n"
        "            hit = f; break\n"
        "    if hit is None:\n"
        "        res = {'engine': 'ghidra', 'mode': 'function', 'program_name': prog_name, 'image_base': img_base_hex, 'target': target, 'error': 'Ghidra 未找到目标函数。'}\n"
        "    else:\n"
        "        ifc = DecompInterface(); ifc.openProgram(currentProgram)\n"
        "        dec = ifc.decompileFunction(hit, 30, monitor)\n"
        "        completed = bool(dec and dec.decompileCompleted())\n"
        "        code_fn = dec.getDecompiledFunction() if completed else None\n"
        "        code_txt = code_fn.getC() if code_fn else ''\n"
        "        if not completed: res = {'engine': 'ghidra', 'mode': 'function', 'target': target, 'error': 'Ghidra 反编译未完成。'}\n"
        "        elif not code_txt.strip(): res = {'engine': 'ghidra', 'mode': 'function', 'target': target, 'error': 'Ghidra 返回了空伪代码。'}\n"
        "        else: res = {'engine': 'ghidra', 'mode': 'function', 'program_name': prog_name, 'image_base': img_base_hex, 'target': target, 'pseudocode': code_txt[:32768], 'disassembly': ''}\n"
        "with open(os.environ['DSH_OUT'], 'w') as fh: fh.write(json.dumps(res))\n"
    )
    def run_headless(args, env):
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except OSError:
                pass
        proc = subprocess.run(
            [ghidra_bin, *args],
            capture_output=True, text=True, errors="replace", timeout=headless_timeout, env=env,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[:2048]
            raise RuntimeError(f"analyzeHeadless 退出码 {proc.returncode}。{detail}")
        if not os.path.isfile(out_path):
            raise RuntimeError("analyzeHeadless 成功退出但没有生成结果 JSON。")
        with open(out_path) as fh:
            result = json.loads(fh.read())
        if not isinstance(result, dict):
            raise RuntimeError("Ghidra 结果不是 JSON 对象。")
        if result.get("mode") == "function" and not result.get("error") \
                and not (result.get("pseudocode") or result.get("disassembly")):
            raise RuntimeError("Ghidra 结果没有伪代码或反汇编。")
        return result
    try:
        with open(script_path, "w") as fh:
            fh.write(py_script)
        env = dict(os.environ)
        env["DSH_TARGET"] = func_target or ""
        env["DSH_OUT"] = out_path
        ghidra_home_tmp = os.path.join(script_dir, "home")
        os.makedirs(ghidra_home_tmp, exist_ok=True)
        env["HOME"] = ghidra_home_tmp
        env["XDG_CONFIG_HOME"] = os.path.join(ghidra_home_tmp, ".config")
        env["XDG_CACHE_HOME"] = os.path.join(ghidra_home_tmp, ".cache")
        java_opts = env.get("JAVA_TOOL_OPTIONS", "").strip()
        env["JAVA_TOOL_OPTIONS"] = (java_opts + f" -Duser.home={ghidra_home_tmp}").strip()

        cache_parent = os.path.join(".ctf-cache", "ghidra")
        cache_dir = None
        bin_sha = None
        try:
            bin_sha = file_sha256(bin_path)
            os.makedirs(cache_parent, exist_ok=True)
            cache_dir = os.path.join(cache_parent, bin_sha[:16])
        except OSError:
            cache_dir = None

        if cache_dir and os.path.isfile(os.path.join(cache_dir, "proj.gpr")) and os.path.isdir(os.path.join(cache_dir, "proj.rep")):
            meta_path = os.path.join(cache_dir, "meta.json")
            prog_name = os.path.basename(bin_path)
            meta_ok = False
            if os.path.isfile(meta_path):
                try:
                    with open(meta_path) as mf:
                        meta = json.loads(mf.read())
                    if meta.get("sha256") == bin_sha and meta.get("program"):
                        prog_name = meta["program"]
                        meta_ok = True
                except Exception:
                    meta_ok = False
            if meta_ok:
                cached_res = run_headless(
                    [cache_dir, "proj", "-process", prog_name, "-noanalysis", "-readOnly", "-scriptPath", script_dir, "-postScript", "DshDecomp.py"],
                    env,
                )
                if cached_res is not None:
                    cached_res.pop("program_name", None)
                    cached_res["cached_project"] = True
                    return cached_res
            shutil.rmtree(cache_dir, ignore_errors=True)

        if cache_dir:
            stage_dir = tempfile.mkdtemp(prefix=f".tmp_{bin_sha[:12]}_", dir=cache_parent)
            try:
                res = run_headless(
                    [stage_dir, "proj", "-import", bin_path, "-scriptPath", script_dir, "-postScript", "DshDecomp.py"],
                    env,
                )
                if res is not None:
                    prog_name = res.pop("program_name", os.path.basename(bin_path))
                    if os.path.isfile(os.path.join(stage_dir, "proj.gpr")):
                        try:
                            with open(os.path.join(stage_dir, "meta.json"), "w") as mf:
                                mf.write(json.dumps({"sha256": bin_sha, "program": prog_name}))
                            os.replace(stage_dir, cache_dir)
                            stage_dir = None
                        except OSError:
                            pass
                    res["cached_project"] = False
                    return res
                return None
            finally:
                if stage_dir:
                    shutil.rmtree(stage_dir, ignore_errors=True)

        ephemeral_dir = tempfile.mkdtemp(prefix="dsh_ghidra_")
        try:
            res = run_headless(
                [ephemeral_dir, "proj", "-import", bin_path, "-scriptPath", script_dir, "-postScript", "DshDecomp.py", "-deleteProject"],
                env,
            )
            if res is not None:
                res.pop("program_name", None)
                res["cached_project"] = False
            return res
        finally:
            shutil.rmtree(ephemeral_dir, ignore_errors=True)
    except Exception as exc:
        ghidra_diagnostic = str(exc)[:2048] or type(exc).__name__
        return None
    finally:
        shutil.rmtree(script_dir, ignore_errors=True)

def with_ghidra_fallback(report):
    if ghidra_diagnostic:
        report["fallback_warning"] = "Ghidra 失败，已尝试其他分析器：" + ghidra_diagnostic
    return report

def disasm_elf_ptload(objdump_bin, bin_path, addr):
    try:
        with open(bin_path, "rb") as fh:
            data = fh.read(32 * 1024 * 1024)
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return None
        is64 = data[4] == 2
        ep = "<" if data[5] == 1 else ">"
        e_machine = struct.unpack_from(ep + "H", data, 18)[0]
        arch_map = {62: ("i386:x86-64", ["-M", "intel"]), 3: ("i386", ["-M", "intel"]), 183: ("aarch64", []), 40: ("arm", [])}
        if e_machine not in arch_map:
            return None
        bfd_arch, extra = arch_map[e_machine]
        if is64:
            phoff = struct.unpack_from(ep + "Q", data, 32)[0]
            phentsize, phnum = struct.unpack_from(ep + "HH", data, 54)
        else:
            phoff = struct.unpack_from(ep + "I", data, 28)[0]
            phentsize, phnum = struct.unpack_from(ep + "HH", data, 42)
        for i in range(phnum):
            off = phoff + i * phentsize
            if is64:
                p_type, _pf, p_off, p_va, _pa, p_fsz, _pmsz, _pa2 = struct.unpack_from(ep + "IIQQQQQQ", data, off)
            else:
                p_type, p_off, p_va, _pa, p_fsz, _pmsz, _pf, _pa2 = struct.unpack_from(ep + "IIIIIIII", data, off)
            if p_type == 1 and p_va <= addr < p_va + p_fsz:
                file_off = p_off + (addr - p_va)
                chunk = data[file_off:min(file_off + 0x200, p_off + p_fsz)]
                if not chunk:
                    return None
                with tempfile.NamedTemporaryFile(delete=False) as tf:
                    tf.write(chunk)
                    tmp_path = tf.name
                try:
                    return run([objdump_bin, "-D", "-b", "binary", "-m", bfd_arch, *extra, f"--adjust-vma={hex(addr)}", tmp_path], timeout=20)
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
    except Exception:
        return None
    return None

if prefer_engine == "ghidra" and ghidra:
    gh_res = decompile_ghidra(ghidra, binary, target)
    if gh_res is not None:
        print(json.dumps(gh_res))
        sys.exit(0)

if r2:
    engine_name = "rizin" if os.path.basename(r2) == "rizin" else "radare2"
    if target is None:
        code, out, err = run([r2, "-e", "bin.relocs.apply=true", "-2", "-A", "-q", "-c", "aflj", "--", binary])
        funcs = []
        try:
            for item in json.loads(out or "[]")[:200]:
                funcs.append({"name": item.get("name"), "address": hex(item.get("offset", 0)), "size": item.get("size", 0)})
        except Exception:
            pass
        r2_report = {"engine": engine_name, "mode": "list", "function_count": len(funcs), "functions": funcs, "exit_code": code, "stderr": err[:2048]}
        if code != 0:
            r2_report["error"] = f"r2 列出函数失败，退出码 {code}。"
        elif not funcs:
            r2_report["warning"] = "r2 没有识别到函数。"
        print(json.dumps(with_ghidra_fallback(r2_report)))
        sys.exit(0)
    r2_cmds = "; ".join([
        "e scr.color=0",
        "?e __DSH_R2_PDG__",
        f"pdg @ {target}",
        "?e __DSH_R2_PDC__",
        f"pdc @ {target}",
        "?e __DSH_R2_ASM__",
        f"pdf @ {target}",
        f"axt @ {target}",
    ])
    code, out, err = run([r2, "-e", "bin.relocs.apply=true", "-2", "-A", "-q", "-c", r2_cmds, "--", binary], timeout=60)
    sections = parse_r2_sections(out)
    pseudo = clean_r2_pseudo(sections["__DSH_R2_PDG__"]) or clean_r2_pseudo(sections["__DSH_R2_PDC__"])
    asm = sections["__DSH_R2_ASM__"]
    if not asm and not pseudo:
        asm = "\n".join(line for line in out.splitlines()
                          if line.strip() not in ("__DSH_R2_PDG__", "__DSH_R2_PDC__", "__DSH_R2_ASM__")).strip()
    r2_report = {"engine": engine_name, "mode": "function", "target": target, "pseudocode": pseudo[:32768], "disassembly": asm[:32768], "exit_code": code, "stderr": err[:2048]}
    if code != 0:
        r2_report["error"] = f"r2 反编译失败，退出码 {code}。"
    elif not pseudo and not asm:
        r2_report["error"] = "r2 没有返回伪代码或反汇编。"
    print(json.dumps(with_ghidra_fallback(r2_report)))
    sys.exit(0)

if ghidra and prefer_engine != "ghidra":
    gh_res = decompile_ghidra(ghidra, binary, target)
    if gh_res is not None:
        print(json.dumps(gh_res))
        sys.exit(0)

objdump = shutil.which("objdump")
readelf = shutil.which("readelf")
nm = shutil.which("nm")
if not objdump:
    print(json.dumps(with_ghidra_fallback({"engine": "none", "error": "沙箱内未找到 r2/radare2 或 objdump。"})))
    sys.exit(2)

if target is None:
    funcs = []
    if readelf:
        code, out, err = run([readelf, "-Ws", "--", binary], timeout=20)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[3] == "FUNC" and parts[6] != "UND":
                try:
                    addr = int(parts[1], 16)
                    size = int(parts[2], 0)
                    funcs.append({"name": parts[7], "address": hex(addr), "size": size})
                except ValueError:
                    pass
    if not funcs and nm:
        code, out, err = run([nm, "-C", "--defined-only", "--", binary], timeout=20)
        for line in out.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[1] in ("T", "t"):
                funcs.append({"name": parts[2], "address": "0x" + parts[0].lstrip("0") or "0x0", "size": 0})
    seen = set()
    unique = []
    for item in funcs:
        key = (item["name"], item["address"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    objdump_report = {"engine": "objdump", "mode": "list", "function_count": len(unique), "functions": unique[:200], "note": "沙箱内未安装 radare2/Ghidra，已降级为符号函数表；指定 function 可用 objdump 反汇编。"}
    if not unique:
        objdump_report["warning"] = "没有识别到可列出的符号函数。"
    print(json.dumps(with_ghidra_fallback(objdump_report)))
    sys.exit(0)

if re.fullmatch(r"0x[0-9a-fA-F]+", target):
    start = int(target, 16)
    cmd = [objdump, "-d", "-M", "intel", f"--start-address={hex(start)}", f"--stop-address={hex(start + 0x400)}", "--", binary]
else:
    start = None
    cmd = [objdump, "-d", "-M", "intel", f"--disassemble={target}", "--", binary]
code, out, err = run(cmd, timeout=30)
engine = "objdump"
if not re.search(r"^\s*[0-9a-f]+:\s+[0-9a-f]{2}", out, re.M):
    if start is not None:
        raw_res = disasm_elf_ptload(objdump, binary, start)
        if raw_res is not None and raw_res[0] == 0 and raw_res[1].strip():
            code, out, err, engine = raw_res[0], raw_res[1], raw_res[2], "objdump_raw"
    if not re.search(r"^\s*[0-9a-f]+:\s+[0-9a-f]{2}", out, re.M):
        gdb_bin = shutil.which("gdb")
        if gdb_bin:
            gdb_cmd = [
                gdb_bin, "-q", "-batch", "-nx", "-nh",
                "-iex", "set auto-load off",
                "-iex", "set debuginfod enabled off",
                "-iex", "set disassembly-flavor intel",
                "--", binary,
                "-ex", f"disassemble {target}",
            ]
            g_code, g_out, g_err = run(gdb_cmd, timeout=30)
            if g_code == 0 and g_out.strip():
                code, out, err, engine = g_code, g_out, g_err, "gdb"
objdump_report = {"engine": engine, "mode": "function", "target": target, "pseudocode": None, "disassembly": out[:49152], "exit_code": code, "stderr": err[:2048], "note": "当前使用汇编输出；安装 radare2/r2ghidra 可输出伪 C。"}
if code != 0 or not out.strip():
    objdump_report["error"] = "objdump 没有成功返回反汇编结果。"
print(json.dumps(with_ghidra_fallback(objdump_report)))
`;

const PWN_TRIAGE_SCRIPT = String.raw`
import json, re, shutil, subprocess, sys

binary = sys.argv[1]
allow_exec = len(sys.argv) > 2 and sys.argv[2] == "1"

def run(cmd, timeout=20):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        return {"ok": proc.returncode == 0, "code": proc.returncode, "stdout": proc.stdout[:16384], "stderr": proc.stderr[:4096]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

report = {"binary": binary}
if shutil.which("file"):
    report["file"] = run(["file", "-b", "--", binary])["stdout"].strip()
if shutil.which("checksec"):
    chk = run(["checksec", "--output=json", f"--file={binary}"])
    if chk.get("ok") and chk["stdout"].strip().startswith("{"):
        try:
            report["checksec"] = json.loads(chk["stdout"])
        except Exception:
            report["checksec_text"] = chk["stdout"][:4096]
    else:
        chk2 = run(["checksec", f"--file={binary}"])
        report["checksec_text"] = (chk2.get("stdout") or chk2.get("stderr") or "")[:4096]
if shutil.which("readelf"):
    dyn = run(["readelf", "-d", "--", binary])
    needed = re.findall(r"Shared library:\s*\[([^\]]+)\]", dyn.get("stdout", ""))
    interp = run(["readelf", "-l", "--", binary])
    m = re.search(r"Requesting program interpreter:\s*([^\]]+)\]", interp.get("stdout", ""))
    report["needed"] = needed[:32]
    report["interpreter"] = m.group(1).strip() if m else None
if shutil.which("ldd"):
    ldd_res = run(["ldd", "--", binary], timeout=10)
    libc_m = re.search(r"libc\.so\.\d+\s*=>\s*(\S+)", ldd_res.get("stdout", ""))
    if libc_m:
        libc_path = libc_m.group(1)
        libc_info = {"path": libc_path}
        if shutil.which("strings"):
            st = run(["strings", "-n", "12", "--", libc_path], timeout=10)
            bm = re.search(r"GNU C Library[^\n]{0,160}", st.get("stdout", ""))
            if bm:
                libc_info["banner"] = bm.group(0).strip()
        report["libc"] = libc_info

rop = shutil.which("ROPgadget")
if rop:
    res = run([rop, "--binary", binary, "--nosys"], timeout=30)
    interesting = []
    pat = re.compile(r":\s*(?:ret|pop (?:rdi|rsi|rdx|rax|rbx|rcx|rbp)(?: ; pop [a-z0-9]+)? ; ret|leave ; ret|syscall(?: ; ret)?)$")
    for line in res.get("stdout", "").splitlines():
        if pat.search(line.strip()):
            interesting.append(line.strip())
            if len(interesting) >= 40:
                break
    report["gadgets"] = {"source": "ROPgadget", "matches": interesting}
else:
    report["gadgets"] = {"source": "unavailable", "note": "沙箱未安装 ROPgadget，可参考 inspect_elf 的基础 gadget 扫描或 objdump。"}

seccomp = shutil.which("seccomp-tools")
if seccomp and allow_exec:
    report["seccomp"] = run([seccomp, "dump", "./" + binary if not binary.startswith("/") else binary], timeout=15)
else:
    report["seccomp"] = {
        "installed": bool(seccomp),
        "executed": False,
        "note": "传入 allow_exec: true 可运行 seccomp-tools dump 检查沙箱系统调用限制。" if seccomp else "沙箱未安装 seccomp-tools。",
    }

print(json.dumps(report))
`;

async function readScriptPreview(cwd, rel) {
  try {
    const fh = await open(path.join(cwd, rel), 'r');
    try {
      const buf = Buffer.alloc(SCRIPT_PREVIEW_BYTES);
      const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
      return buf.subarray(0, bytesRead).toString('utf8');
    } finally {
      await fh.close();
    }
  } catch {
    return undefined;
  }
}

function executionMeta(detected, need, plan) {
  const meta = {
    ...(plan.profile ? { profile: plan.profile } : {}),
    ...(plan.autoUpgraded ? { auto_upgraded: true, upgrade_reasons: plan.upgradeReasons } : {}),
    ...(plan.profileFallbackReason ? { profile_fallback_reason: plan.profileFallbackReason } : {}),
  };
  if (detected.preference === 'auto' && detected.backend === 'wsl') {
    meta.fallback_reason = detected.docker.reason;
    if (need.preferDocker) {
      meta.arsenal_note = '当前任务适合完整 Docker 兵器库或离线容器隔离，但 Docker 暂不可用，已自动回退 WSL2；若缺工具可构建镜像 dsh-ctf-sandbox:latest（重器可叠加 dsh-ctf-sandbox:heavy）。';
    }
  }
  return meta;
}

export async function runSandbox(args, { cwd, config = {}, signal, writable, checkWorkspaceFile }) {
  const action = args.action;
  if (!['status', 'exec', 'decompile', 'pwn_triage'].includes(action)) {
    throw new ToolError('unsupported', 'action 须为 status、exec、decompile 或 pwn_triage。');
  }
  if (args.backend !== undefined && !['auto', 'docker', 'wsl'].includes(args.backend)) {
    throw new ToolError('unsupported', 'backend 须为 auto、docker 或 wsl。');
  }
  const requestedProfile = args.profile ?? 'auto';
  if (!['auto', 'base', 'heavy'].includes(requestedProfile)) {
    throw new ToolError('unsupported', 'profile 须为 auto、base 或 heavy。');
  }
  const hasExplicitTimeout = args.timeout_ms !== undefined;
  const timeoutMs = args.timeout_ms ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < MIN_TIMEOUT_MS || timeoutMs > MAX_TIMEOUT_MS) {
    throw new ToolError('unsupported', `timeout_ms 须在 ${MIN_TIMEOUT_MS} 至 ${MAX_TIMEOUT_MS} 内。`);
  }
  const effectiveConfig = args.backend !== undefined ? { ...config, sandboxBackend: args.backend } : config;

  if (action === 'status') {
    const detected = await detectSandbox(effectiveConfig, signal, { fresh: true });
    if (!detected.available) return { status: 'unavailable', ...detected };
    const statusPlan = detected.backend === 'docker'
      ? (requestedProfile === 'base'
        ? resolveExecutionPlan(detected, { preferHeavy: false }, 'base')
        : detected.docker?.heavy?.available
          ? resolveExecutionPlan(detected, { preferHeavy: true }, 'heavy')
          : resolveExecutionPlan(detected, { preferHeavy: false }, 'base'))
      : resolveExecutionPlan(detected, { preferHeavy: false }, 'auto');
    try {
      const probe = await runSandboxCommand(['python3', '-c', PROBE_SCRIPT], {
        cwd, config: effectiveConfig, signal, timeoutMs: Math.min(timeoutMs, 15000), readOnlyWork: true, detected,
        image: statusPlan.image, profile: statusPlan.profile,
      });
      if (probe.code === 0) {
        const parsed = JSON.parse(probe.stdout.trim());
        return {
          status: 'ok',
          ...detected,
          probed_profile: probe.profile,
          probed_target: probe.target,
          environment: parsed,
          elapsed_ms: probe.elapsed_ms,
        };
      }
      return {
        status: 'partial',
        ...detected,
        probed_profile: probe.profile,
        probed_target: probe.target,
        stderr: truncateText(probe.stderr, 2048).text,
        elapsed_ms: probe.elapsed_ms,
      };
    } catch (error) {
      return { status: 'partial', ...detected, error: describeToolError(error) };
    }
  }

  if (!writable) throw new ToolError('permission', `当前会话为只读权限，无法执行沙箱操作 ${action}。`);

  if (action === 'exec') {
    const hasCommand = typeof args.command === 'string' && args.command.trim().length > 0;
    const hasScript = typeof args.script_path === 'string' && args.script_path.trim().length > 0;
    if (hasCommand === hasScript) {
      throw new ToolError('unsupported', 'exec 须在 command 与 script_path 中二选一。');
    }
    if (args.network !== undefined && !['none', 'bridge'].includes(args.network)) {
      throw new ToolError('unsupported', 'network 须为 none 或 bridge。');
    }
    if (args.ptrace !== undefined && typeof args.ptrace !== 'boolean') {
      throw new ToolError('unsupported', 'ptrace 须为布尔值。');
    }
    if (args.read_only_work !== undefined && typeof args.read_only_work !== 'boolean') {
      throw new ToolError('unsupported', 'read_only_work 须为布尔值。');
    }
    let argv;
    let scriptPreview;
    if (hasCommand) {
      if (args.command.length > MAX_COMMAND_CHARS || /[\0]/u.test(args.command)) {
        throw new ToolError('unsupported', 'command 长度超限或包含非法空字节。');
      }
      argv = ['bash', '-lc', args.command];
    } else {
      const rel = await checkWorkspaceFile(args.script_path);
      if (rel.endsWith('.py')) {
        scriptPreview = await readScriptPreview(cwd, rel);
        argv = ['python3', '--', rel];
      } else if (rel.endsWith('.sage')) {
        argv = ['sage', rel];
      } else if (rel.endsWith('.sh')) {
        argv = ['bash', '-c', "set -o pipefail; sed 's/\\r$//' -- \"$1\" | bash -s", 'ctf-script', rel];
      } else {
        argv = ['./' + rel];
      }
    }
    const need = analyzeSandboxNeed(args, { scriptPreview });
    const detected = await detectSandbox(effectiveConfig, signal);
    const plan = resolveExecutionPlan(detected, need, requestedProfile);
    const meta = executionMeta(detected, need, plan);
    const result = await runSandboxCommand(argv, {
      cwd, config: effectiveConfig, signal, timeoutMs,
      network: args.network ?? 'none',
      ptrace: args.ptrace === true,
      readOnlyWork: args.read_only_work === true,
      requiresIsolation: true,
      detected,
      image: plan.image,
      profile: plan.profile,
    });
    const out = truncateText(result.stdout);
    const err = truncateText(result.stderr);
    return {
      action: 'exec',
      status: result.timedOut ? 'timeout' : result.code === 0 ? 'ok' : 'failed',
      backend: result.backend,
      target: result.target,
      network: result.backend === 'docker' ? (args.network ?? 'none') : 'host_shared_wsl',
      ...meta,
      exit_code: result.code,
      elapsed_ms: result.elapsed_ms,
      stdout: out.text,
      stderr: err.text,
      ...(out.truncated || result.stdoutTruncated ? { stdout_truncated: true } : {}),
      ...(err.truncated || result.stderrTruncated ? { stderr_truncated: true } : {}),
    };
  }

  if (typeof args.file_path !== 'string' || args.file_path.trim().length === 0) {
    throw new ToolError('path', `${action} 需要提供题目工作区内的 file_path。`);
  }
  if (action === 'decompile' && args.function !== undefined && (typeof args.function !== 'string' || args.function.length === 0
    || args.function.length > 256 || !/^[A-Za-z0-9_.$:@+-]+$/u.test(args.function))) {
    throw new ToolError('unsupported', 'function 须为合法的函数符号名或十六进制地址。');
  }
  const rel = await checkWorkspaceFile(args.file_path);
  const need = analyzeSandboxNeed(args);
  const detected = await detectSandbox(effectiveConfig, signal);
  let plan = resolveExecutionPlan(detected, need, requestedProfile);
  let meta = executionMeta(detected, need, plan);

  if (action === 'decompile') {
    const runDecompileOnce = async (currentPlan, preferEngine) => {
      const effectiveTimeout = !hasExplicitTimeout && preferEngine === 'ghidra'
        ? HEAVY_DECOMPILE_TIMEOUT_MS : timeoutMs;
      const argv = ['python3', '-c', DECOMPILE_SCRIPT, rel, args.function ?? '', preferEngine, String(effectiveTimeout)];
      return runSandboxCommand(argv, {
        cwd, config: effectiveConfig, signal, timeoutMs: effectiveTimeout, detected,
        requiresIsolation: true,
        image: currentPlan.image, profile: currentPlan.profile,
      });
    };
    const preferEngine = requestedProfile === 'heavy' && plan.profile === 'heavy' ? 'ghidra' : 'auto';
    let result = await runDecompileOnce(plan, preferEngine);
    if (result.timedOut) {
      return { action: 'decompile', status: 'timeout', backend: result.backend, target: result.target, ...meta, elapsed_ms: result.elapsed_ms };
    }
    let report;
    try {
      report = JSON.parse(result.stdout.trim());
    } catch {
      return {
        action: 'decompile', status: 'failed', backend: result.backend, target: result.target, ...meta, exit_code: result.code,
        stdout: truncateText(result.stdout, 16384).text, stderr: truncateText(result.stderr, 8192).text,
      };
    }
    if (requestedProfile === 'auto' && plan.profile === 'base' && detected.backend === 'docker'
      && detected.docker?.heavy?.available && (report.engine === 'objdump' || report.engine === 'objdump_raw')) {
      const heavyPlan = {
        backend: 'docker',
        profile: 'heavy',
        image: detected.docker.heavy.image,
        autoUpgraded: true,
        upgradeReasons: ['decompile_no_r2_in_base'],
      };
      const retry = await runDecompileOnce(heavyPlan, 'ghidra');
      if (!retry.timedOut) {
        try {
          const retryReport = JSON.parse(retry.stdout.trim());
          if (!retryReport.error) {
            plan = heavyPlan;
            meta = executionMeta(detected, need, plan);
            result = retry;
            report = retryReport;
          }
        } catch { /* keep base result */ }
      }
    }
    return {
      action: 'decompile',
      status: report.error ? 'failed' : 'ok',
      backend: result.backend,
      target: result.target,
      ...meta,
      elapsed_ms: result.elapsed_ms,
      ...report,
    };
  }

  const argv = ['python3', '-c', PWN_TRIAGE_SCRIPT, rel, args.allow_exec === true ? '1' : '0'];
  const result = await runSandboxCommand(argv, {
    cwd, config: effectiveConfig, signal, timeoutMs, ptrace: args.allow_exec === true, readOnlyWork: true, detected,
    requiresIsolation: true,
    image: plan.image, profile: plan.profile,
  });
  if (result.timedOut) {
    return { action: 'pwn_triage', status: 'timeout', backend: result.backend, target: result.target, ...meta, elapsed_ms: result.elapsed_ms };
  }
  try {
    const report = JSON.parse(result.stdout.trim());
    return {
      action: 'pwn_triage', status: 'ok', backend: result.backend, target: result.target,
      ...meta, elapsed_ms: result.elapsed_ms, ...report,
    };
  } catch {
    return {
      action: 'pwn_triage', status: 'failed', backend: result.backend, target: result.target, ...meta, exit_code: result.code,
      stdout: truncateText(result.stdout, 16384).text, stderr: truncateText(result.stderr, 8192).text,
    };
  }
}
