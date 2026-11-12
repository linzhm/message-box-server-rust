// Fixed Git-source SDK Writer and middleware helpers; no server or crypto.
import { pathToFileURL } from 'node:url';
const sdk = process.env.SDK_SOURCE_DIR, middleware = process.env.AUTH_MIDDLEWARE_SOURCE_DIR;
const { Writer, toArray } = await import(pathToFileURL(`${sdk}/src/primitives/utils.ts`));
const { writeUrlToWriter, writeRequestHeadersToWriter, writeBodyToWriter } = await import(pathToFileURL(`${middleware}/authMiddlewareHelpers.ts`));
const cases = [
  ['/listMessages', {}],
  ['/listMessages?', {messageBox: 'inbox'}],
  ['/listMessages?trace=1', {messageBox: 'inbox'}],
  ['/sendMessage?trace=1', {message: null}],
  ['/acknowledgeMessage?trace=1', {messageIds: [1]}],
  ['/registerDevice?trace=1', {fcmToken: false}],
  ['/permissions/set?trace=1', {messageBox: 'inbox', recipientFee: 'free'}],
  ['/listMessages', {messageBox: 1}],
  ['/sendMessage', {message: null}],
  ['/acknowledgeMessage', {messageIds: [1]}],
  ['/registerDevice', {fcmToken: false}],
  ['/permissions/set', {messageBox: 'inbox', recipientFee: 'free'}],
  ['/listMessages', {messageBox: 'inbox', extra: {values: [true, null, 2, '猫']}}],
  ['/listMessages', {messageBox: 'inbox', metadata: {'0': 'first', '1': 'second', name: 'labels'}}],
  ['/listMessages', {messageBox: 'inbox', metadata: {progress: 1.5, ratio: 0.25}}],
  ['/listMessages', {messageBox: 'inbox', limit: 1.5}],
  ['/listMessages', {messageBox: 'inbox', metadata: {values: [1.5, 0.1, 0.01, -0.25, 999999999.99]}}],
  ['/listMessages', {messageBox: 'inbox', metadata: {values: [0.125, 0.001, 0.03125, -0.0625, 1.000001, 123.456789, 999999999.125, 999999999.000001, -999999999.000001]}}],
  ['/listMessages', {messageBox: 'inbox', limit: 0.125}],
  ['/listMessages', {messageBox: 'inbox', metadata: {note: 'literal 1e-6 "quoted"', values: [0.000001, 0.000002, 0.000003, 0.000004, 0.000005, 0.000006, 0.000007, 0.000008, 0.000009, -0.000001, -0.000002, -0.000003, -0.000004, -0.000005, -0.000006, -0.000007, -0.000008, -0.000009]}}],
  ['/listMessages', {messageBox: 'inbox', limit: 0.000001}],
  ['/listMessages', {messageBox: 'inbox', limit: Math.PI}],
  ['/listMessages', {messageBox: 'inbox', metadata: {values: [Math.PI, 0.12345678901234566, 1.0000001, 0.00001, 0.000001, 0.0000001, -0.0000001, -0.125]}}],
  ['/listMessages', {messageBox: 'inbox', metadata: {negativeZero: -0, safeInteger: 9007199254740991}}],
  ['/permissions/set', {messageBox: 'inbox', recipientFee: 0}],
  ['/permissions/set', {messageBox: 'inbox', recipientFee: Math.PI}],
];
const vectors = cases.map(([path, body]) => {
  const bodyText = JSON.stringify(body);
  const headers = {'content-type': 'application/json', 'content-length': String(Buffer.byteLength(bodyText))};
  const writer = new Writer();
  writer.write(Array(32).fill(3));
  writer.writeVarIntNum(4); writer.write(toArray('POST'));
  writeUrlToWriter(new URL(`http://localhost${path}`), writer);
  writeRequestHeadersToWriter({headers}, writer);
  writeBodyToWriter({headers, body}, writer);
  return {path, body: bodyText, frameHex: Buffer.from(writer.toArray()).toString('hex')};
});
const peer = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const extraTargets = [
  '/devices?',
  '/permissions/list?',
  '/permissions/get?',
  '/permissions/quote?',
  `/permissions/quote?recipient=${peer}&messageBox=inbox`,
  `/permissions/quote?messageBox=inbox&recipient=${peer}`,
  '/permissions/quote?recipient=bad&messageBox=inbox',
  '/permissions/quote?messageBox=inbox&recipient=bad',
  '/permissions/quote?recipient=bad&messageBox=inbox&recipient=alsoBad',
  '/permissions/quote',
  '/permissions/quote?recipient=bad',
  '/permissions/quote?messageBox=inbox',
  `/permissions/quote?${Array(101).fill('recipient=bad').join('&')}&messageBox=inbox`,
  `/permissions/get?messageBox=inbox&sender=${peer}`,
  '/permissions/get',
  '/permissions/get?sender=bad',
  `/permissions/get?sender=${peer}&messageBox=inbox`,
  '/permissions/get?messageBox=inbox&sender=bad',
  '/permissions/get?sender=bad&messageBox=inbox',
  '/permissions/list?messageBox=inbox&limit=1&offset=0',
  '/permissions/list?offset=0&limit=1&messageBox=inbox',
  '/permissions/list?messageBox=inbox&offset=0&limit=1',
  '/permissions/list?limit=1&messageBox=inbox&offset=0',
  '/permissions/list?limit=1&offset=0&messageBox=inbox',
  '/permissions/list?offset=0&messageBox=inbox&limit=1',
  '/permissions/list?messageBox=inbox&limit=1&offset=bad',
  '/permissions/list?offset=bad&limit=1&messageBox=inbox',
  '/permissions/list?createdAtOrder=asc&limit=1&offset=0&messageBox=inbox',
  '/permissions/list?messageBox=inbox&offset=0&limit=1&createdAtOrder=asc',
  '/permissions/list?createdAtOrder=bad&limit=1',
  '/permissions/list?limit=1&createdAtOrder=bad',
];
for (const target of ['/devices?limit=bad', '/devices?limit=01', '/permissions/list?limit=bad', '/devices?offset=0&limit=1', '/devices?offset=bad&limit=1', ...extraTargets]) {
  const writer = new Writer(); writer.write(Array(32).fill(3));
  writer.writeVarIntNum(3); writer.write(toArray('GET'));
  const url = new URL(`http://localhost${target}`);
  writeUrlToWriter(url, writer);
  writeRequestHeadersToWriter({headers: {}}, writer);
  writeBodyToWriter({headers: {}, body: {}}, writer);
  vectors.push({path: target, body: '', frameHex: Buffer.from(writer.toArray()).toString('hex')});
}
console.log(JSON.stringify({source:'ts-stack 52d36a5 SDK 4.0.1 Writer and auth middleware helpers; no server or cryptography', vectors}, null, 2));
