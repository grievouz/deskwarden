import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { DeskwardenClient, parseKey } from '../src/client.ts';
import { type Harness, startHarness } from './harness.ts';

describe('DeskwardenClient', () => {
  let harness: Harness;
  let client: DeskwardenClient;

  before(async () => {
    harness = await startHarness();
    client = new DeskwardenClient({ key: harness.key, socketPath: harness.socketPath });
  });

  after(async () => {
    client.close();
    await harness.stop();
  });

  test('reads built-in and custom fields', async () => {
    assert.equal(await client.get('Infra/Postgres prod'), 'pg-secret');
    assert.equal(await client.get('Infra/Postgres prod', 'username'), 'app');
    assert.equal(await client.get('Infra/Postgres prod', 'port'), '5432');
    assert.equal(await client.get('Deploy notes', 'notes'), 'line one\nline two');
  });

  test('uses the folder to tell items with the same name apart', async () => {
    assert.equal(await client.get('Infra/Stripe'), 'sk_test_infra');
    assert.equal(await client.get('Personal/Stripe'), 'sk_test_personal');
    assert.equal(await client.get('7a1b2c3d-0000-4000-8000-000000000002'), 'sk_test_personal');
  });

  test('reports missing and ambiguous items', async () => {
    await assert.rejects(client.get('Infra/Nope'), { code: 'not_found' });
    await assert.rejects(client.get('Stripe'), { code: 'ambiguous' });
    await assert.rejects(client.get('Infra/Stripe', 'username'), { code: 'field_not_found' });
  });

  test('answers many concurrent requests on one connection', async () => {
    const values = await Promise.all(Array.from({ length: 50 }, () => client.get('Infra/Stripe')));
    assert.deepEqual(new Set(values), new Set(['sk_test_infra']));
  });
});

describe('connection failures', () => {
  test('rejects a key id the server does not know', async () => {
    const harness = await startHarness();
    const client = new DeskwardenClient({
      key: `dwk_0011223344556677_${randomBytes(32).toString('base64url')}`,
      socketPath: harness.socketPath,
    });
    await assert.rejects(client.get('Infra/Stripe'), { code: 'unauthorized' });
    await harness.stop();
  });

  test('rejects a known key id with the wrong secret', async () => {
    const harness = await startHarness();
    const { id } = parseKey(harness.key);
    const client = new DeskwardenClient({
      key: `dwk_${id}_${randomBytes(32).toString('base64url')}`,
      socketPath: harness.socketPath,
    });
    await assert.rejects(client.get('Infra/Stripe'), { code: 'unauthorized' });
    await harness.stop();
  });

  test('reports a missing socket as unavailable', async () => {
    const harness = await startHarness();
    const client = new DeskwardenClient({ key: harness.key, socketPath: `${harness.socketPath}.missing` });
    await assert.rejects(client.get('Infra/Stripe'), { code: 'unavailable' });
    await harness.stop();
  });

  test('reports a denied approval', async () => {
    const harness = await startHarness({ DESKWARDEN_HARNESS_DENY: '1' });
    const client = new DeskwardenClient({ key: harness.key, socketPath: harness.socketPath });
    await assert.rejects(client.get('Infra/Stripe'), { code: 'denied' });
    client.close();
    await harness.stop();
  });

  test('reports a locked vault', async () => {
    const harness = await startHarness({ DESKWARDEN_HARNESS_LOCKED: '1' });
    const client = new DeskwardenClient({ key: harness.key, socketPath: harness.socketPath });
    await assert.rejects(client.get('Infra/Stripe'), { code: 'locked' });
    client.close();
    await harness.stop();
  });

  test('rejects strings that are not Deskwarden keys', () => {
    assert.throws(() => parseKey('not-a-key'), { code: 'unauthorized' });
    assert.throws(() => parseKey('dwk_0011_tooshort'), { code: 'unauthorized' });
  });
});
