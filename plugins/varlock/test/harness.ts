import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';

const repoRoot = resolve(import.meta.dirname, '../../..');

let harnessBin: string | undefined;

/** Builds Sources/SocketHarness once per test run. */
function buildHarness(): string {
  if (!harnessBin) {
    execFileSync('swift', ['build', '--product', 'SocketHarness'], { cwd: repoRoot, stdio: ['ignore', 'ignore', 'inherit'] });
    const binDir = execFileSync('swift', ['build', '--show-bin-path'], { cwd: repoRoot, encoding: 'utf8' }).trim();
    harnessBin = join(binDir, 'SocketHarness');
  }
  return harnessBin;
}

export interface Harness {
  socketPath: string;
  key: string;
  stop(): Promise<void>;
}

/** Starts the real secrets socket on a temporary path, serving fixture items. */
export async function startHarness(env: Record<string, string> = {}): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), 'dw-'));
  const socketPath = join(dir, 's.sock');
  const child = spawn(buildHarness(), [socketPath], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const key = await new Promise<string>((resolve, reject) => {
    createInterface({ input: child.stdout }).on('line', (line) => {
      const match = /^READY (\S+)$/.exec(line);
      if (match) resolve(match[1]);
    });
    child.on('exit', (code) => reject(new Error(`SocketHarness exited with ${code}`)));
  });
  return {
    socketPath,
    key,
    async stop() {
      child.kill();
      if (child.exitCode === null) await once(child, 'exit');
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
