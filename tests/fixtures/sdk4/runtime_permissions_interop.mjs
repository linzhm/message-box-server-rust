// Fixed high-level client against the real loopback runtime, with synthetic
// keys and a temporary SQLite database. No payments or external network.
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
const { AuthFetch } = await import(pathToFileURL(`${sdk}/src/auth/clients/AuthFetch.ts`));
const { default: ProtoWallet } = await import(pathToFileURL(`${sdk}/src/wallet/ProtoWallet.ts`));
const { default: PrivateKey } = await import(pathToFileURL(`${sdk}/src/primitives/PrivateKey.ts`));
const dir = await mkdtemp(join(tmpdir(), 'messagebox-permissions-'));
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
function wallet(n) {
  const value = new ProtoWallet(new PrivateKey(n));
  value.createAction = async () => { throw new Error('Payments disabled in test'); };
  return value;
}
try {
  const ready = await start();
  const host = `http://${ready.address}/mb`;
  const server = new PrivateKey(3).toPublicKey().toString();
  const aliceId = new PrivateKey(2).toPublicKey().toString();
  const bobId = new PrivateKey(4).toPublicKey().toString();
  const carolId = new PrivateKey(5).toPublicKey().toString();
  const client = n => new MessageBoxClient({
    host, walletClient: wallet(n), serverIdentityKeysByHost: { [host]: server }
  });
  const alice = client(2);
  const bob = client(4);
  const carol = client(5);

  assert.equal(await bob.getMessageBoxPermission({ recipient: bobId, messageBox: 'inbox' }, host), null);
  await bob.setMessageBoxPermission({ messageBox: 'inbox', recipientFee: 0 }, host);
  await bob.setMessageBoxPermission({ messageBox: 'inbox', recipientFee: -1, sender: aliceId }, host);
  const wide = await bob.getMessageBoxPermission({ recipient: bobId, messageBox: 'inbox' }, host);
  const scoped = await bob.getMessageBoxPermission({ recipient: bobId, messageBox: 'inbox', sender: aliceId }, host);
  assert.equal(wide.recipientFee, 0);
  assert.equal(scoped.recipientFee, -1);
  const first = await bob.listMessageBoxPermissions({ messageBox: 'inbox', limit: 1, offset: 0 }, host);
  const second = await bob.listMessageBoxPermissions({ messageBox: 'inbox', limit: 1, offset: 1 }, host);
  assert.equal(first.length, 1);
  assert.equal(second.length, 1);
  assert.deepEqual(new Set([first[0].sender, second[0].sender]), new Set([null, aliceId]));
  assert.deepEqual(await carol.listMessageBoxPermissions({ messageBox: 'inbox' }, host), []);
  assert.equal(await carol.getMessageBoxPermission({ recipient: bobId, messageBox: 'inbox' }, host), null);
  assert.equal((await alice.getMessageBoxQuote({ recipient: bobId, messageBox: 'inbox' }, host)).recipientFee, -1);
  assert.equal((await carol.getMessageBoxQuote({ recipient: bobId, messageBox: 'inbox' }, host)).recipientFee, 0);
  await assert.rejects(alice.sendMessage({
    recipient: bobId, messageBox: 'inbox', messageId: 'blocked', body: 'fake',
    skipEncryption: true, checkPermissions: true
  }, host), /blocked/i);
  await assert.rejects(alice.sendMessage({
    recipient: bobId, messageBox: 'inbox', messageId: 'blocked-server', body: 'fake',
    skipEncryption: true, checkPermissions: false
  }, host), /HTTP 403/i);
  assert.deepEqual(await bob.listMessagesLite({ messageBox: 'inbox' }), []);
  const partial = await alice.sendMessageToRecipients({
    recipients: [bobId, carolId], messageBox: 'inbox', body: 'allowed only', skipEncryption: true
  }, host);
  assert.equal(partial.status, 'success');
  assert.deepEqual(partial.blocked, [bobId]);
  assert.equal(partial.sent.length, 1);
  assert.equal(partial.sent[0].recipient, carolId);
  assert.deepEqual(await bob.listMessagesLite({ messageBox: 'inbox' }), []);
  const carolMessages = await carol.listMessagesLite({ messageBox: 'inbox' });
  assert.equal(carolMessages.length, 1);
  assert.equal(carolMessages[0].messageId, partial.sent[0].messageId);
  assert.equal(carolMessages[0].body, 'allowed only');
  assert.equal(await carol.acknowledgeMessage({ messageIds: [partial.sent[0].messageId], host }), 'success');
  const directAuth = new AuthFetch(wallet(2), undefined, undefined, undefined, { responseTimeoutMs: 3000 });
  const directBatch = await directAuth.fetch(`${host}/sendMessage`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ message: { recipients: [bobId, carolId], messageBox: 'inbox',
      messageId: ['direct-bob', 'direct-carol'], body: 'should not be stored' } }),
    requireMutualAuth: true, expectedIdentityKey: server, allowPayments: false
  });
  assert.equal(directBatch.status, 403);
  const directResult = await directBatch.json();
  assert.equal(directResult.code, 'ERR_DELIVERY_BLOCKED');
  assert.deepEqual(directResult.blockedRecipients, [bobId]);
  assert.deepEqual(await bob.listMessagesLite({ messageBox: 'inbox' }), []);
  assert.deepEqual(await carol.listMessagesLite({ messageBox: 'inbox' }), []);


  await bob.setMessageBoxPermission({ messageBox: 'inbox', recipientFee: 0, sender: aliceId }, host);
  const sent = await alice.sendMessage({
    recipient: bobId, messageBox: 'inbox', messageId: 'allowed', body: 'fake',
    skipEncryption: true, checkPermissions: true
  }, host);
  assert.equal(sent.messageId, 'allowed');
  await bob.setMessageBoxPermission({ messageBox: 'inbox', recipientFee: 7, sender: aliceId }, host);
  assert.equal((await alice.getMessageBoxQuote({ recipient: bobId, messageBox: 'inbox' }, host)).recipientFee, 7);

  config.bind = ready.address;
  await writeFile(configFile, JSON.stringify(config));
  await stop();
  const restarted = await start();
  assert.equal(restarted.address, ready.address);
  assert.equal(restarted.identityKey, server);
  assert.equal((await bob.getMessageBoxPermission({ recipient: bobId, messageBox: 'inbox', sender: aliceId }, host)).recipientFee, 7);
  assert.equal((await alice.getMessageBoxQuote({ recipient: bobId, messageBox: 'inbox' }, host)).recipientFee, 7);
  assert.equal((await bob.listMessagesLite({ messageBox: 'inbox' }))[0].messageId, 'allowed');
  assert.equal(await bob.acknowledgeMessage({ messageIds: ['allowed'], host }), 'success');
  assert.deepEqual(await bob.listMessagesLite({ messageBox: 'inbox' }), []);
  await stop();
  console.log('Fixed MessageBoxClient permission, quote, isolation and restart paths passed on loopback; no payment.');
} finally {
  if (child && child.exitCode === null && child.signalCode === null) {
    const exited = once(child, 'exit');
    child.kill('SIGKILL');
    await exited.catch(() => {});
  }
  await rm(dir, { recursive: true, force: true });
}
