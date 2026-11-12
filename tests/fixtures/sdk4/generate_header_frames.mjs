// Fixed Git-source SDK Writer and auth middleware helpers; no server or crypto.
import { pathToFileURL } from 'node:url';
const sdk = process.env.SDK_SOURCE_DIR, middleware = process.env.AUTH_MIDDLEWARE_SOURCE_DIR;
const { Writer, toArray } = await import(pathToFileURL(`${sdk}/src/primitives/utils.ts`));
const { writeUrlToWriter, writeRequestHeadersToWriter, writeBodyToWriter } = await import(pathToFileURL(`${middleware}/authMiddlewareHelpers.ts`));
const peer = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const contentType = 'application/JSON; charset=utf-8';
const cases = [
  ['POST', '/listMessages', {messageBox: 'inbox'}],
  ['POST', '/sendMessage', {message: null}],
  ['POST', '/acknowledgeMessage', {messageIds: [1]}],
  ['POST', '/registerDevice', {fcmToken: false}],
  ['POST', '/permissions/set', {messageBox: 'inbox', recipientFee: 'free'}],
  ['GET', '/devices', undefined],
  ['GET', '/permissions/get?messageBox=inbox', undefined],
  ['GET', '/permissions/list', undefined],
  ['GET', `/permissions/quote?recipient=${peer}&messageBox=inbox`, undefined],
];
const vectors = cases.map(([method, path, body]) => {
  const bodyText = body === undefined ? '' : JSON.stringify(body);
  const headers = {'content-type': contentType};
  if (body !== undefined) headers['content-length'] = String(Buffer.byteLength(bodyText));
  const writer = new Writer();
  writer.write(Array(32).fill(3)); writer.writeVarIntNum(method.length); writer.write(toArray(method));
  writeUrlToWriter(new URL(`http://localhost${path}`), writer);
  writeRequestHeadersToWriter({headers}, writer);
  writeBodyToWriter({headers, body: body ?? {}}, writer);
  return {method, path, body: bodyText, contentType, frameHex: Buffer.from(writer.toArray()).toString('hex')};
});
console.log(JSON.stringify({source:'ts-stack 52d36a5 SDK Writer and auth middleware helpers; no server or cryptography', vectors}, null, 2));
