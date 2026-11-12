// Exact pinned sendMessage remittance checks with fixed SDK source; synthetic values only.
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const evidence=JSON.parse(await readFile(process.env.TS_SERVER_EVIDENCE,'utf8'));
const source=evidence.files['infra/message-box-server/src/routes/sendMessage.ts'].content, bytes=Buffer.from(source);
const sha=createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
assert.equal(sha,'1279ce37c009e1cc37419824673f1ac4403b0510');
const start=source.indexOf('function validDerivationToken('),end=source.indexOf('async function anyoneIdentityKey(',start);
assert.ok(start>=0 && end>start);
const ts=(await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
const js=ts.transpileModule(source.slice(start,end)+'\nreturn hasCanonicalDeliveryRemittance(payment, sender);',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const {default:PublicKey}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/primitives/PublicKey.ts`));
const {toArray,toBase64}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/primitives/utils.ts`));
const run=new Function('payment','sender','PublicKey','toArray','toBase64','MAX_PAYMENT_DERIVATION_BYTES',js);
const sender='0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const remittance={derivationPrefix:'AQ==',derivationSuffix:'Ag==',senderIdentityKey:sender};
const output={outputIndex:0,protocol:'wallet payment',paymentRemittance:remittance};
const variants=[output,{...output,outputIndex:1},{...output,outputIndex:-1},{...output,outputIndex:1.5},{...output,outputIndex:9007199254740991},{...output,outputIndex:9007199254740992},{...output,protocol:'basket insertion'},{...output,paymentRemittance:null},
 ...['','A','AA=','AB==','AA==','aA==','////','AA==\n','A'.repeat(128),'A'.repeat(132)].map(derivationPrefix=>({...output,paymentRemittance:{...remittance,derivationPrefix}})),
 ...[sender.toUpperCase(),'00',sender+'00','02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'].map(senderIdentityKey=>({...output,paymentRemittance:{...remittance,senderIdentityKey}}))];
const cases=variants.map(output=>({output,sender,expected:run({outputs:[output]},sender,PublicKey,toArray,toBase64,128)}));
await writeFile(process.argv[2],JSON.stringify({sourceBlob:sha,cases},null,2)+'\n');
console.log(`Generated ${cases.length} delivery remittance vectors.`);
