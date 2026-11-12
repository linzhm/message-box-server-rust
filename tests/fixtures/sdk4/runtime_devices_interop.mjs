// Fixed high-level client, synthetic device tokens and a disposable loopback
// runtime. No Firebase access, real credentials, payments or external network.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import assert from 'node:assert/strict';

const sdk = process.env.SDK_SOURCE_DIR;
const clientSource = process.env.CLIENT_SOURCE_DIR;
const { MessageBoxClient } = await import(pathToFileURL(
  `${clientSource}/packages/messaging/message-box-client/src/MessageBoxClient.ts`
));
const { default: ProtoWallet } = await import(pathToFileURL(`${sdk}/src/wallet/ProtoWallet.ts`));
const { default: PrivateKey } = await import(pathToFileURL(`${sdk}/src/primitives/PrivateKey.ts`));
const dir = await mkdtemp(join(tmpdir(), 'messagebox-devices-'));
const key = join(dir, 'identity.key');
const configFile = join(dir, 'config.json');
await writeFile(key, '0'.repeat(63) + '3\n', { mode: 0o600 });
const config = {
  bind: '127.0.0.1:0', dataDir: dir, identityKeyFile: key,
  pricingMode: 'ts-table', routingPrefix: '/mb'
};
await writeFile(configFile, JSON.stringify(config));

let child;
async function start() {
  child = spawn(process.env.MESSAGEBOX_SERVER, [configFile], { stdio: ['ignore', 'pipe', 'inherit'] });
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  const ready = await Promise.race([
    lines.next(),
    once(child, 'exit').then(([code]) => { throw new Error(`early exit ${code}`); }),
    new Promise((_, reject) => setTimeout(() => reject(new Error('startup timeout')), 10000))
  ]);
  return JSON.parse(ready.value);
}
async function stop() {
  const exit = once(child, 'exit', { signal: AbortSignal.timeout(10000) });
  child.kill('SIGINT');
  assert.equal((await exit)[0], 0);
  child = undefined;
}
try {
  const ready = await start();
  const host = `http://${ready.address}/mb`;
  const server = new PrivateKey(3).toPublicKey().toString();
  const client = n => {
    const walletClient = new ProtoWallet(new PrivateKey(n));
    walletClient.createAction = async () => { throw new Error('Payments disabled in test'); };
    return new MessageBoxClient({ host, walletClient, serverIdentityKeysByHost: { [host]: server } });
  };
  const bob = client(4);
  const carol = client(5);
  const token = 'synthetic-device-token-0000000001';
  const registered = await bob.registerDevice({ fcmToken: token, deviceId: 'old', platform: 'ios' }, host);
  const refreshed = await bob.registerDevice({ fcmToken: token, deviceId: 'new', platform: 'android' }, host);
  assert.equal(refreshed.deviceId, registered.deviceId);
  await assert.rejects(carol.registerDevice({ fcmToken: token, deviceId: 'stolen', platform: 'web' }, host), /HTTP 409/);
  const afterConflict = await bob.listRegisteredDevices(host);
  assert.equal(afterConflict.length, 1);
  assert.equal(afterConflict[0].id, registered.deviceId);
  assert.equal(afterConflict[0].deviceId, 'new');
  assert.equal(afterConflict[0].platform, 'android');
  assert.equal(afterConflict[0].fcmToken, '...0000000001');
  assert.deepEqual(await carol.listRegisteredDevices(host), []);

  await new Promise(resolve => setTimeout(resolve, 5));
  const second = await bob.registerDevice({ fcmToken: 'synthetic-device-token-0000000002', deviceId: 'second', platform: 'web' }, host);
  await new Promise(resolve => setTimeout(resolve, 5));
  const third = await bob.registerDevice({ fcmToken: 'synthetic-device-token-0000000003', deviceId: 'third', platform: 'ios' }, host);
  const pages = [];
  for (let offset = 0; offset < 3; offset++) {
    const page = await bob.listRegisteredDevices(host, { limit: 1, offset });
    assert.equal(page.length, 1);
    pages.push(page[0].id);
  }
  assert.deepEqual(new Set(pages), new Set([registered.deviceId, second.deviceId, third.deviceId]));
  assert.deepEqual(await bob.listRegisteredDevices(host, { limit: 1, offset: 3 }), []);
  await assert.rejects(bob.listRegisteredDevices(host, { limit: 0 }), RangeError);

  config.bind = ready.address;
  await writeFile(configFile, JSON.stringify(config));
  await stop();
  const restarted = await start();
  assert.equal(restarted.address, ready.address);
  assert.equal(restarted.identityKey, server);
  const afterRestart = await bob.listRegisteredDevices(host);
  assert.deepEqual(new Set(afterRestart.map(device => device.id)), new Set(pages));
  for (const [id, deviceId, platform, suffix] of [
    [registered.deviceId, 'new', 'android', '0000000001'],
    [second.deviceId, 'second', 'web', '0000000002'],
    [third.deviceId, 'third', 'ios', '0000000003']
  ]) {
    const device = afterRestart.find(item => item.id === id);
    assert.equal(device.deviceId, deviceId);
    assert.equal(device.platform, platform);
    assert.equal(device.fcmToken, `...${suffix}`);
    assert.equal(device.active, true);
  }
  assert.deepEqual(await carol.listRegisteredDevices(host), []);
  await stop();
  console.log('Fixed MessageBoxClient device refresh, ownership, pagination and restart passed on loopback; no Firebase.');
} finally {
  if (child && child.exitCode === null && child.signalCode === null) {
    const exited = once(child, 'exit');
    child.kill('SIGKILL');
    await exited.catch(() => {});
  }
  await rm(dir, { recursive: true, force: true });
}
