// Run with SDK_ROOT and AUTH_MIDDLEWARE_ROOT pointing to the SRI-verified
// package directories for the fixed server lock. Both packages must resolve
// @bsv/sdk normally. No wallet, network, device or credentials are used.
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { parse as parseQuery } from 'node:querystring'
const sdkRoot = resolve(process.env.SDK_ROOT ?? 'node_modules/@bsv/sdk')
const middlewareRoot = resolve(process.env.AUTH_MIDDLEWARE_ROOT ?? 'node_modules/@bsv/auth-express-middleware')
const load = path => import(pathToFileURL(path).href)
const { Writer, toArray } = await load(`${sdkRoot}/dist/esm/src/primitives/utils.js`)
const { AuthFetch } = await load(`${sdkRoot}/dist/esm/src/auth/clients/AuthFetch.js`)
const { writeUrlToWriter, writeRequestHeadersToWriter, writeBodyToWriter } = await load(`${middlewareRoot}/dist/src/authMiddlewareHelpers.mjs`)
for (const [root, expected] of [[sdkRoot, '4.0.1'], [middlewareRoot, '2.3.0']]) {
  if (JSON.parse(readFileSync(`${root}/package.json`)).version !== expected) throw Error('wrong package version')
}
const source = JSON.parse(readFileSync(`${middlewareRoot}/dist/src/authMiddlewareHelpers.mjs.map`)).sourcesContent[0]
const helperBlob = createHash('sha1').update(`blob ${Buffer.byteLength(source)}\0`).update(source).digest('hex')
if (helperBlob !== '223b41e28d21fd20486775137cce15b67653a42f') throw Error('helper differs from fixed Git source')
const sdkSourceBlobs = {}
for (const [path, expected] of [
  ['auth/clients/AuthFetch', '39deb8677cf2e9267c2a5cb4d9d84d2ece2aa5d8'],
  ['wallet/BRC100ByteEncoding', '434feeb5674ab96a2f6872b83be351e41574afdf'],
  ['primitives/utils', 'bc84d4a71a316498b17124de184ee1b412aa92c8'],
]) {
  const source = JSON.parse(readFileSync(`${sdkRoot}/dist/esm/src/${path}.js.map`)).sourcesContent[0]
  const blob = createHash('sha1').update(`blob ${Buffer.byteLength(source)}\0`).update(source).digest('hex')
  if (blob !== expected) throw Error(`SDK source differs: ${path}`)
  sdkSourceBlobs[path] = blob
}
const sdk = new AuthFetch({})
const vectors = []
async function add(name, method, target, body, headers, status, code) {
  const reqHeaders = { host: 'localhost', ...headers }
  if (body !== undefined) reqHeaders['content-length'] = String(Buffer.byteLength(body))
  const parsedBody = body === undefined || body === '' ? undefined : JSON.parse(body)
  const url = new URL(`http://localhost${target}`)
  const writer = new Writer()
  writer.write(Array(32).fill(3)); writer.writeVarIntNum(method.length); writer.write(toArray(method))
  writeUrlToWriter(url, writer)
  writeRequestHeadersToWriter({ headers: reqHeaders }, writer)
  writeBodyToWriter({ body: parsedBody, headers: reqHeaders }, writer)
  const client = await sdk.serializeRequest(method, headers, body, url, Array(32).fill(3))
  const vector = { name, method, target, body: body ?? '', headers, status, code,
    frameHex: Buffer.from(writer.toArray()).toString('hex'),
    sdkStringFrameHex: Buffer.from(client.toArray()).toString('hex'),
    query: parseQuery(target.split('?').slice(1).join('?')) }
  vectors.push(vector)
}
const json = { 'content-type': 'application/json' }
for (const [name, body] of [
  ['whitespace', ' { "messageBox" : "inbox", "limit":1.00 } \n'],
  ['duplicates', '{"messageBox":"discarded","messageBox":"inbox","metadata":{"a":1,"a":2}}'],
  ['index-order', '{"messageBox":"inbox","metadata":{"name":"n","10":"ten","2":"two","01":"other","0":"zero","4294967295":"ordinary","4294967294":"last"}}'],
  ['escapes', '{"messageBox":"inbox","metadata":{"unicode":"\\u732b\\ud83d\\udce8","slash":"a\\/b","control":"\\u0001"}}'],
  ['numbers', '{"messageBox":"inbox","metadata":{"values":[1.0000000000000002,1000000000.5,1e-7,1E-6,1e20,1e21,1e+30,1.7976931348623157e308,5e-324,9007199254740993,18446744073709551615,-9223372036854775809]}}'],
  ['integer-fields', '{"messageBox":"inbox","limit":1e0,"offset":0.0}'],
  ['all-token-headers', '{"messageBox":"inbox"}'],
]) {
  const headers = { ...json }
  if (name === 'all-token-headers') {
    for (const c of "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz") {
      for (const suffix of ['', 'a', '_', '-']) headers[`x-bsv-${c}${suffix}`] = `value-${c}${suffix}`
    }
    headers.authorization = 'Bearer synthetic-example'
  }
  await add(name, 'POST', '/listMessages?trace=a%20b&extra=%2f&flag', body, headers, 200, null)
}
await add('invalid-fraction', 'POST', '/listMessages', '{"messageBox":"inbox","limit":3.141592653589793}', json, 400, 'ERR_INVALID_LIMIT')
await add('unsafe-limit', 'POST', '/listMessages', '{"messageBox":"inbox","limit":9007199254740993}', json, 400, 'ERR_INVALID_LIMIT')
for (const [name, body] of [['empty-array','[]'],['byte-array','[0,1.0,255]'],['general-array','["x",256,{}]']]) {
  await add(name, 'POST', '/listMessages', body, json, 400, 'ERR_MESSAGEBOX_REQUIRED')
}
await add('empty-body', 'POST', '/sendMessage', '', json, 400, 'ERR_MESSAGE_REQUIRED')
await add('extra-fields', 'GET', '/devices?limit=1&trace=a%20b&meta[x]=2', undefined, {}, 200, null)
await add('duplicate-limit', 'GET', '/devices?limit=1&limit=2', undefined, {}, 400, 'ERR_INVALID_LIMIT')
await add('encoded-query', 'GET', '/permissions/get?messageBox=%69nbox&trace=%2f&flag', undefined, {}, 200, null)
await add('plus-query', 'GET', '/permissions/get?messageBox=a+b&extra=x', undefined, {}, 200, null)
await add('space-query', 'GET', '/permissions/get?messageBox=a%20b&extra=x', undefined, {}, 200, null)
await add('duplicate-box', 'GET', '/permissions/get?messageBox=a&messageBox=b', undefined, {}, 400, 'ERR_INVALID_MESSAGE_BOX')
await add('apostrophe-query', 'GET', "/permissions/get?messageBox=a'b", undefined, {}, 200, null)
await add('lenient-query', 'GET', '/permissions/get?messageBox=%E7%8C%AB&extra=%zz&bad=%c0%af&empty=&=x&&flag', undefined, {}, 200, null)
await add('header-case', 'GET', '/devices?', undefined, { 'content-type': 'Application/JSON; charset=UTF-8', authorization: 'Bearer example', 'x-bsv-z': 'last', 'x-bsv-a': 'first' }, 200, null)
const peer='0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
await add('send-custom', 'POST', '/sendMessage?extra=%20', JSON.stringify({message:{recipient:peer,messageBox:'inbox',messageId:'custom-proof-message',body:'untampered'}}), {...json,'x-bsv-extra':'signed-value'}, 200, null)
await add('payment-deferred', 'POST', '/sendMessage', JSON.stringify({message:{recipient:peer,messageBox:'inbox',messageId:'deferred-message',body:'must-not-store'}}), {...json,'x-bsv-payment':'synthetic-not-a-payment'}, 501, 'ERR_PAYMENT_NOT_IMPLEMENTED')
const queryCases = [
  'a=1&a=2&__proto__=x&constructor=y&nested[x]=z&array[]=one',
  'plus=a+b&space=a%20b&percent=%2f&malformed=%zz&bad=%c0%af&empty=&=x&&flag',
  `${'x=&'.repeat(1000)}last=excluded`,
  `${'&'.repeat(999)}last=included&next=excluded`,
].map(query => ({ query, parsed: parseQuery(query) }))
const output = { source: 'Fixed TS middleware helper (exact Git blob) plus SDK 4.0.1 from the fixed server npm lock. Frame generation only, no authentication or running TS server.', businessExpectations: 'Hand-authored application assertions, not captured TS server responses.', helperBlob, sdkSourceBlobs, node: process.version, queryCases, locale: new Intl.Collator().resolvedOptions().locale, vectors }
writeFileSync('tests/fixtures/http-compat-sdk4-lock.json', JSON.stringify(output, null, 2)+'\n')
console.log(JSON.stringify({vectors:vectors.length,helperBlob,distinctClientFrames:vectors.filter(v=>v.frameHex!==v.sdkStringFrameHex).map(v=>v.name)}))
