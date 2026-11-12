// Fixed SDK/MessageBoxClient against a disposable loopback runtime.
// Public test keys, synthetic data, no payment and no external network.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import assert from 'node:assert/strict';

const nativeFetch = globalThis.fetch;
const pageTraffic = [];
globalThis.fetch = async (url, init) => {
  const response = await nativeFetch(url, init);
  const headers = new Headers(init?.headers);
  if (String(url).endsWith('/listMessages') && headers.has('x-bsv-auth-request-id')) {
    pageTraffic.push({
      request: JSON.parse(String(init.body)),
      response: await response.clone().json()
    });
  }
  return response;
};

const sdk = process.env.SDK_SOURCE_DIR;
const clientSource = process.env.CLIENT_SOURCE_DIR;
const { MessageBoxClient } = await import(pathToFileURL(
  `${clientSource}/packages/messaging/message-box-client/src/MessageBoxClient.ts`
));
const { AuthFetch } = await import(pathToFileURL(`${sdk}/src/auth/clients/AuthFetch.ts`));
const { default: ProtoWallet } = await import(pathToFileURL(`${sdk}/src/wallet/ProtoWallet.ts`));
const { default: PrivateKey } = await import(pathToFileURL(`${sdk}/src/primitives/PrivateKey.ts`));

const dir = await mkdtemp(join(tmpdir(), 'messagebox-encrypted-'));
const key = join(dir, 'identity.key');
const config = join(dir, 'config.json');
await writeFile(key, '0'.repeat(63) + '3\n', { mode: 0o600 });
await writeFile(config, JSON.stringify({
  bind: '127.0.0.1:0',
  dataDir: dir,
  identityKeyFile: key,
  pricingMode: 'ts-table',
  routingPrefix: '/mb'
}));

let child;
try {
  child = spawn(process.env.MESSAGEBOX_SERVER, [config], { stdio: ['ignore', 'pipe', 'inherit'] });
  const readyLine = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  const ready = await Promise.race([
    readyLine.next(),
    once(child, 'exit').then(([code]) => { throw new Error(`early exit ${code}`); }),
    new Promise((_, reject) => setTimeout(() => reject(new Error('startup timeout')), 10000))
  ]);
  const address = JSON.parse(ready.value).address;
  const host = `http://${address}/mb`;
  const server = new PrivateKey(3).toPublicKey().toString();
  const wallet = n => {
    const value = new ProtoWallet(new PrivateKey(n));
    value.createAction = async () => { throw new Error('Payments disabled in test'); };
    return value;
  };
  const aliceWallet = wallet(2);
  const bobWallet = wallet(4);
  const carolWallet = wallet(5);
  const aliceId = new PrivateKey(2).toPublicKey().toString();
  const bobId = new PrivateKey(4).toPublicKey().toString();
  const carolId = new PrivateKey(5).toPublicKey().toString();
  const client = walletClient => new MessageBoxClient({
    host, walletClient, serverIdentityKeysByHost: { [host]: server }
  });
  const alice = client(aliceWallet);
  const bob = client(bobWallet);
  const carol = client(carolWallet);

  const secret = 'private payload α 📦';
  const sent = await alice.sendMessage({
    recipient: bobId, messageBox: 'inbox', body: secret, checkPermissions: false
  }, host);
  assert.equal(sent.status, 'success');
  assert.match(sent.messageId, /^[0-9a-f]{64}$/);
  const rawAuth = new AuthFetch(bobWallet, undefined, undefined, undefined, { responseTimeoutMs: 3000 });
  const raw = await rawAuth.fetch(`${host}/listMessages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ messageBox: 'inbox' }),
    requireMutualAuth: true,
    expectedIdentityKey: server,
    allowPayments: false
  });
  assert.equal(raw.status, 200);
  const rows = (await raw.json()).messages;
  const ciphertext = rows.find(row => row.messageId === sent.messageId);
  assert.ok(ciphertext);
  assert.match(ciphertext.body, /encryptedMessage/);
  assert.equal(ciphertext.body.includes(secret), false);
  const bobList = await bob.listMessagesLite({ messageBox: 'inbox' });
  assert.equal(bobList.find(row => row.messageId === sent.messageId)?.body, secret);
  assert.equal(bobList.find(row => row.messageId === sent.messageId)?.sender, aliceId);
  assert.deepEqual(await alice.listMessagesLite({ messageBox: 'inbox' }), []);
  assert.deepEqual(await carol.listMessagesLite({ messageBox: 'inbox' }), []);

  await assert.rejects(alice.sendMessageToRecipients({
    recipients: [bobId, carolId], messageBox: 'inbox', body: 'encrypted batch'
  }, host), /cannot be encrypted per recipient/i);
  const batch = await alice.sendMessageToRecipients({
    recipients: [bobId, carolId], messageBox: 'inbox', body: 'shared batch', skipEncryption: true
  }, host);
  assert.equal(batch.status, 'success');
  assert.equal(batch.sent.length, 2);
  const bobBatch = batch.sent.find(item => item.recipient === bobId).messageId;
  const carolBatch = batch.sent.find(item => item.recipient === carolId).messageId;
  assert.notEqual(bobBatch, carolBatch);
  const bobAfter = await bob.listMessagesLite({ messageBox: 'inbox' });
  const carolAfter = await carol.listMessagesLite({ messageBox: 'inbox' });
  assert.equal(bobAfter.find(row => row.messageId === bobBatch)?.body, 'shared batch');
  assert.equal(carolAfter.find(row => row.messageId === carolBatch)?.body, 'shared batch');
  assert.equal(bobAfter.find(row => row.messageId === bobBatch)?.sender, aliceId);
  assert.equal(carolAfter.find(row => row.messageId === carolBatch)?.sender, aliceId);
  assert.equal(bobAfter.some(row => row.messageId === carolBatch), false);
  assert.equal(carolAfter.some(row => row.messageId === bobBatch || row.messageId === sent.messageId), false);
  assert.equal(await bob.acknowledgeMessage({ messageIds: [sent.messageId, bobBatch], host }), 'success');
  assert.equal(await carol.acknowledgeMessage({ messageIds: [carolBatch], host }), 'success');
  assert.deepEqual(await bob.listMessagesLite({ messageBox: 'inbox' }), []);
  assert.deepEqual(await carol.listMessagesLite({ messageBox: 'inbox' }), []);

  const ids = [];
  for (let i = 0; i < 5; i++) {
    const messageId = `page-${i}`;
    const pageSend = await alice.sendMessage({
      recipient: bobId, messageBox: 'inbox', messageId, body: `page body ${i}`,
      skipEncryption: true, checkPermissions: false
    }, host);
    assert.equal(pageSend.messageId, messageId);
    ids.push(messageId);
  }
  const pageStart = pageTraffic.length;
  const pages = await bob.listMessagesLite({ messageBox: 'inbox', pageSize: 2 });
  assert.equal(pages.length, 5);
  assert.deepEqual(new Set(pages.map(item => item.messageId)), new Set(ids));
  const observed = pageTraffic.slice(pageStart);
  assert.deepEqual(observed.map(item => [item.request.offset, item.request.limit]), [[0, 2], [2, 2], [4, 2]]);
  assert.deepEqual(observed.map(item => item.response.messages.length), [2, 2, 1]);
  assert.deepEqual(observed.map(item => item.response.hasMore), [true, true, false]);
  await assert.rejects(bob.listMessagesLite({ messageBox: 'inbox', pageSize: 2, maxPages: 2 }), /pagination exceeded/i);
  assert.equal(await bob.acknowledgeMessage({ messageIds: ids, host }), 'success');
  assert.deepEqual(await bob.listMessagesLite({ messageBox: 'inbox' }), []);

  const exit = once(child, 'exit', { signal: AbortSignal.timeout(10000) });
  child.kill('SIGINT');
  assert.equal((await exit)[0], 0);
  child = undefined;
  console.log('Fixed MessageBoxClient encrypted single, shared batch and automatic pagination verified against loopback runtime; no payment.');
} finally {
  globalThis.fetch = nativeFetch;
  if (child && child.exitCode === null && child.signalCode === null) {
    const exited = once(child, 'exit');
    child.kill('SIGKILL');
    await exited.catch(() => {});
  }
  await rm(dir, { recursive: true, force: true });
}
