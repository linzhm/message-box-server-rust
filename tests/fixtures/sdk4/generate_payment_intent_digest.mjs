// Executes the exact pinned private paymentIntentDigest function using synthetic data.
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
const evidence = JSON.parse(await readFile(process.env.TS_SERVER_EVIDENCE, 'utf8'));
const source = evidence.files['infra/message-box-server/src/routes/sendMessage.ts'].content;
const bytes = Buffer.from(source, 'utf8');
const sha = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
assert.equal(sha, '1279ce37c009e1cc37419824673f1ac4403b0510');
const start = source.indexOf('function paymentIntentDigest(');
const end = source.indexOf('async function preparePaymentIntent(', start);
assert.ok(start >= 0 && end > start);
const ts = (await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
const js = ts.transpileModule(source.slice(start, end) + '\nreturn paymentIntentDigest(validated, sender, payment, transactionId);', { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText;
const run = new Function('validated', 'sender', 'payment', 'transactionId', 'createHash', 'Buffer', js);
function calculate(input) {
  let preimage;
  const hashing = algorithm => ({ update(value, encoding) { preimage = value; return { digest(format) { return createHash(algorithm).update(value, encoding).digest(format); } }; } });
  const {sender, message, payment} = input;
  const validated = {boxType: message.boxType, recipients: message.recipients, messageIds: message.messageIds, message: {body: message.body}};
  const digest = run(validated, sender, payment, payment.transactionId, hashing, Buffer);
  return {input, preimage, digest};
}
const remittance = {derivationPrefix:'AQ==', derivationSuffix:'Ag==', senderIdentityKey:'02abc'};
const base = {sender:'02sender',message:{boxType:'inbox',recipients:['02recipient'],messageIds:['m-1'],body:'hello'},payment:{transactionId:'abc123',tx:[0,1,2,255],outputs:[{outputIndex:0,protocol:'wallet payment',paymentRemittance:remittance}],description:'Payment for message'}};
const cases = [base,
  {...base, message:{...base.message,body:'猫 😀\n\t"\\\u0000\b\f\r'}},
  {...base, message:{...base.message,recipients:['a','b'],messageIds:['one','two']},payment:{...base.payment,outputs:[base.payment.outputs[0],{outputIndex:1,protocol:'wallet payment',paymentRemittance:{...remittance,derivationSuffix:'Aw=='}}]}},
  {...base,payment:{...base.payment,tx:[],description:''}},
  {...base,payment:{...base.payment,outputs:[{...base.payment.outputs[0],outputIndex:9007199254740991}]}},
  {...base,message:{...base.message,boxType:'通知\u2028',body:'line\u2029break'},payment:{...base.payment,tx:[42]}}
];
const {description: _omitted, ...withoutDescription} = base.payment;
cases.push({...base,payment:withoutDescription});
cases.push({...base,payment:{...base.payment,description:null}});
cases.push({...base,payment:{...base.payment,labels:[],seekPermission:true}});
cases.push({...base,payment:{...base.payment,labels:['a','猫','\n'],seekPermission:false}});
cases.push({...base,payment:{...base.payment,seekPermission:null}});
cases.push({...base,payment:{...base.payment,outputs:[{...base.payment.outputs[0],customInstructions:'recipient metadata'}]}});
cases.push({...base,payment:{...base.payment,outputs:[{...base.payment.outputs[0],customInstructions:null}]}});
cases.push({...base,payment:{...base.payment,outputs:[{...base.payment.outputs[0],paymentRemittance:{...remittance,customInstructions:'\"quoted\"\n猫'}}]}});
cases.push({...base,payment:{...base.payment,outputs:[{...base.payment.outputs[0],paymentRemittance:{...remittance,customInstructions:null},customInstructions:'{\"recipient\":\"alice\"}'}]}});
for (let code = 0; code < 32; code++) cases.push({...base, message:{...base.message, body:`before${String.fromCodePoint(code)}after`}});
for (const code of [0x7f,0x80,0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,0x10ffff]) cases.push({...base, message:{...base.message, body:`before${String.fromCodePoint(code)}after`}});
await writeFile(process.argv[2], JSON.stringify({sourceBlob:sha, cases:cases.map(calculate)},null,2)+'\n');
console.log(`Generated ${cases.length} exact source digest vectors.`);
