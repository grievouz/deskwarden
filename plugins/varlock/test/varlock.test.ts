import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { startHarness } from './harness.ts';

const pluginPath = resolve(import.meta.dirname, '../dist/plugin.cjs');
const varlockBin = resolve(import.meta.dirname, '../node_modules/.bin/varlock');

// Needs `tsdown` to have built dist/plugin.cjs; `pnpm test` does that first.
test('varlock resolves deskwarden() through the built plugin', async () => {
  const harness = await startHarness();
  const project = mkdtempSync(join(tmpdir(), 'dw-varlock-'));
  writeFileSync(join(project, '.env.schema'), [
    `# @plugin(${pluginPath})`,
    `# @initDeskwarden(key=$DESKWARDEN_KEY, socketPath="${harness.socketPath}")`,
    '# ---',
    '# @type=deskwardenKey',
    'DESKWARDEN_KEY=',
    'DB_PASSWORD=deskwarden("Infra/Postgres prod")',
    'DB_USER=deskwarden("Infra/Postgres prod", field=username)',
    'DB_PORT=deskwarden("5f0c6d1e-2b8a-4c3e-9a51-1d2f3e4a5b6c", field=port)',
    '',
  ].join('\n'));

  try {
    const { stdout } = await promisify(execFile)(varlockBin, ['load', '--format', 'json', '--skip-cache'], {
      cwd: project,
      env: { ...process.env, DESKWARDEN_KEY: harness.key, VARLOCK_TELEMETRY_DISABLED: 'true' },
    });
    const env = JSON.parse(stdout);
    assert.equal(env.DB_PASSWORD, 'pg-secret');
    assert.equal(env.DB_USER, 'app');
    assert.equal(env.DB_PORT, '5432');
  } finally {
    rmSync(project, { recursive: true, force: true });
    await harness.stop();
  }
});
