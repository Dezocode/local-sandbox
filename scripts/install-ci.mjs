import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  accessSync,
  constants,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { projectRoot } from "./sites-env.mjs";
import { readExecutionProfile } from "./execution-profile.mjs";

const STALE_OWNER_GRACE_MS = 30_000;

export function parsePackageManager(value) {
  const match = /^pnpm@(\d+\.\d+\.\d+)$/.exec(value ?? "");
  if (!match) throw new Error("package.json must pin an exact pnpm version.");
  return match[1];
}

export function parseDuration(value, fallbackMs) {
  if (!value) return fallbackMs;
  const match = /^(\d+)(ms|s|m)?$/.exec(value);
  if (!match) throw new Error(`Invalid duration: ${value}`);
  const unit = match[2] ?? "ms";
  const multiplier = unit === "m" ? 60_000 : unit === "s" ? 1_000 : 1;
  const duration = Number(match[1]) * multiplier;
  if (!Number.isSafeInteger(duration) || duration < 1_000 || duration > 60 * 60_000) {
    throw new Error(`Duration is outside the supported range: ${value}`);
  }
  return duration;
}

function ensureDirectory(directory) {
  try {
    const current = lstatSync(directory);
    if (current.isSymbolicLink() || !current.isDirectory()) {
      throw new Error(`Expected a real directory: ${directory}`);
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const created = lstatSync(directory);
    if (created.isSymbolicLink() || !created.isDirectory()) {
      throw new Error(`Could not create a safe directory: ${directory}`);
    }
  }
}

function readOwner(ownerPath) {
  const stat = lstatSync(ownerPath);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 4096) {
    throw Object.assign(new Error("Install lock owner is not a regular file."), { exitCode: 78 });
  }
  const owner = JSON.parse(readFileSync(ownerPath, "utf8"));
  if (!Number.isSafeInteger(owner?.pid) || owner.pid <= 0 ||
      typeof owner?.nonce !== "string" || !/^[0-9a-f-]{36}$/.test(owner.nonce) ||
      typeof owner?.startedAt !== "string") {
    throw Object.assign(new Error("Install lock owner is invalid."), { exitCode: 78 });
  }
  return owner;
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== "ESRCH";
  }
}

export class PortableInstallLease {
  constructor(lockDirectory) {
    this.lockDirectory = lockDirectory;
    this.ownerPath = path.join(lockDirectory, "owner.json");
    this.nonce = randomUUID();
    this.held = false;
  }

  acquire() {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        mkdirSync(this.lockDirectory, { mode: 0o700 });
        writeFileSync(this.ownerPath, `${JSON.stringify({
          version: 1,
          pid: process.pid,
          nonce: this.nonce,
          startedAt: new Date().toISOString(),
        })}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
        this.held = true;
        return;
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
      }

      const lockStat = lstatSync(this.lockDirectory);
      if (lockStat.isSymbolicLink() || !lockStat.isDirectory()) {
        throw Object.assign(new Error("Install lock is not a real directory."), { exitCode: 78 });
      }
      const entries = readdirSync(this.lockDirectory);
      if (entries.length === 0) {
        if (Date.now() - lockStat.mtimeMs < STALE_OWNER_GRACE_MS) {
          throw Object.assign(new Error("Another dependency install is acquiring the lock."), { exitCode: 75 });
        }
        rmdirSync(this.lockDirectory);
        continue;
      }
      if (entries.length !== 1 || entries[0] !== "owner.json") {
        throw Object.assign(new Error("Install lock has unexpected contents."), { exitCode: 78 });
      }
      const owner = readOwner(this.ownerPath);
      if (processIsAlive(owner.pid)) {
        throw Object.assign(new Error(`Another dependency install is already running (pid ${owner.pid}).`), { exitCode: 75 });
      }
      unlinkSync(this.ownerPath);
      rmdirSync(this.lockDirectory);
    }
    throw Object.assign(new Error("Could not acquire the dependency install lock."), { exitCode: 75 });
  }

  release() {
    if (!this.held) return;
    const owner = readOwner(this.ownerPath);
    if (owner.pid !== process.pid || owner.nonce !== this.nonce) {
      throw new Error("Install lock ownership changed; refusing to remove it.");
    }
    unlinkSync(this.ownerPath);
    rmdirSync(this.lockDirectory);
    this.held = false;
  }
}

function resolvePnpm(expectedVersion) {
  const candidates = [];
  if (process.env.SITES_PNPM_BIN) {
    const binary = path.resolve(process.env.SITES_PNPM_BIN);
    const stat = lstatSync(binary);
    if (stat.isSymbolicLink() || !stat.isFile()) throw new Error("SITES_PNPM_BIN must be a regular file.");
    candidates.push({ command: process.execPath, prefix: [binary] });
  }
  candidates.push({ command: "corepack", prefix: ["pnpm"] });
  candidates.push({ command: "pnpm", prefix: [] });

  for (const candidate of candidates) {
    const probe = spawnSync(candidate.command, [...candidate.prefix, "--version"], {
      cwd: projectRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    if (!probe.error && probe.status === 0 && probe.stdout.trim() === expectedVersion) return candidate;
  }
  throw new Error(`This project requires pnpm ${expectedVersion} through Corepack or PATH.`);
}

function signalProcessGroup(child, signal) {
  if (!child.pid) return;
  try {
    if (process.platform === "win32") child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch {
    try { child.kill(signal); } catch {}
  }
}

export async function runBounded(command, args, options = {}) {
  const timeoutMs = options.timeoutMs ?? 8 * 60_000;
  const killAfterMs = options.killAfterMs ?? 15_000;
  const child = spawn(command, args, {
    cwd: options.cwd,
    env: options.env,
    stdio: options.stdio ?? "inherit",
    detached: process.platform !== "win32",
  });
  let timedOut = false;
  let receivedSignal;
  const handlers = ["SIGINT", "SIGHUP", "SIGTERM"].map((signal) => {
    const handler = () => {
      receivedSignal ??= signal;
      signalProcessGroup(child, signal);
    };
    process.on(signal, handler);
    return [signal, handler];
  });
  const timer = setTimeout(() => {
    timedOut = true;
    signalProcessGroup(child, "SIGTERM");
    setTimeout(() => signalProcessGroup(child, "SIGKILL"), killAfterMs).unref();
  }, timeoutMs);
  const result = await new Promise((resolve) => {
    child.once("error", (error) => resolve({ code: error.code === "ENOENT" ? 127 : 1, signal: null }));
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  clearTimeout(timer);
  for (const [signal, handler] of handlers) process.removeListener(signal, handler);
  return { ...result, timedOut, receivedSignal };
}

function writeInstallMarker(lockfilePath, markerPath, packageManager) {
  const marker = {
    package_manager: packageManager,
    lockfile_sha256: createHash("sha256").update(readFileSync(lockfilePath)).digest("hex"),
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
  };
  const temporary = `${markerPath}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(marker, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  renameSync(temporary, markerPath);
}

async function portableInstall() {
  const metadata = JSON.parse(readFileSync(path.join(projectRoot, "package.json"), "utf8"));
  const version = parsePackageManager(metadata.packageManager);
  const packageManager = `pnpm@${version}`;
  const pnpm = resolvePnpm(version);
  const runtimeRoot = path.join(projectRoot, ".sites-runtime");
  const store = path.join(runtimeRoot, "pnpm-store");
  const cache = path.join(store, "policy-cache");
  ensureDirectory(runtimeRoot);
  ensureDirectory(store);
  ensureDirectory(cache);
  const lease = new PortableInstallLease(path.join(runtimeRoot, "portable-install.lock"));
  lease.acquire();
  try {
    const result = await runBounded(pnpm.command, [...pnpm.prefix,
      "install",
      "--frozen-lockfile",
      "--prod=false",
      "--ignore-scripts=false",
      "--prefer-offline",
      "--store-dir", store,
      "--cache-dir", cache,
      "--fetch-retries=0",
      "--fetch-timeout=30000",
      "--network-concurrency=1",
      "--package-import-method=clone-or-copy",
    ], {
      cwd: projectRoot,
      env: { ...process.env, CI: "true" },
      timeoutMs: parseDuration(process.env.SITES_INSTALL_TIMEOUT, 8 * 60_000),
      killAfterMs: parseDuration(process.env.SITES_INSTALL_KILL_AFTER, 15_000),
    });
    if (result.timedOut) throw Object.assign(new Error("Dependency setup timed out."), { exitCode: 124 });
    if (result.code !== 0 || result.signal) {
      throw Object.assign(new Error(`Dependency setup failed (${result.code ?? result.signal}).`), { exitCode: result.code ?? 1 });
    }
    const vinext = path.join(projectRoot, "node_modules", ".bin", process.platform === "win32" ? "vinext.cmd" : "vinext");
    accessSync(vinext, process.platform === "win32" ? constants.F_OK : constants.X_OK);
    writeInstallMarker(path.join(projectRoot, "pnpm-lock.yaml"), path.join(projectRoot, "node_modules", ".sites-install.json"), packageManager);
    process.stdout.write(`[sites] portable dependency setup passed with ${packageManager}\n`);
  } finally {
    lease.release();
  }
}

export async function main() {
  if (readExecutionProfile() === "managed-linux") {
    const result = spawnSync("bash", [path.join(projectRoot, "scripts/install-pnpm.sh")], { stdio: "inherit" });
    if (result.error) throw result.error;
    process.exitCode = result.status ?? 1;
    return;
  }
  await portableInstall();
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "Dependency setup failed."}\n`);
    process.exitCode = error?.exitCode ?? 69;
  }
}
