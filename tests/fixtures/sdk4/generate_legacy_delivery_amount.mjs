// Offline source/SDK oracle. Synthetic, unfunded Atomic BEEF; never payment verification.
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const evidence=JSON.parse(await readFile(process.env.TS_SERVER_EVIDENCE,'utf8'));
const source=evidence.files['infra/message-box-server/src/routes/sendMessage.ts'].content, bytes=Buffer.from(source);
const sha=createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
assert.equal(sha,'1279ce37c009e1cc37419824673f1ac4403b0510');
const start=source.indexOf('function parsePayment('),end=source.indexOf('function aggregateDeliveryFee(',start);
assert.ok(start>=0&&end>start);
const ts=(await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
const js=ts.transpileModule(source.slice(start,end)+'\nconst parsed = parsePayment(payment); return parsed != null && deliveryOutputCoversFee(parsed, payment.outputs[0], fee);',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const {default:Transaction}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/transaction/Transaction.ts`));
const check=new Function('payment','fee','Transaction',js);
const samples=[];
for (const file of ['payment_subject_vectors.json','bump_payment_vectors.json']) {
  const fixture=JSON.parse(await readFile(new URL(file,import.meta.url),'utf8'));
  for (const v of fixture.vectors) samples.push({hex:v.hex,label:`${file}:${v.label??samples.length}`});
}
const cases=[];
for (const sample of samples) {
  const tx=Array.from(Buffer.from(sample.hex,'hex'));
  for (const [index,fee] of [[0,1],[0,100],[0,101],[1,1]]) {
    const output={protocol:'wallet payment',outputIndex:index};
    cases.push({...sample,index,fee,expected:check({tx,outputs:[output]},fee,Transaction)});
  }
}
await writeFile(process.argv[2],JSON.stringify({sourceBlob:sha,cases},null,2)+'\n');
console.log(`Generated ${cases.length} legacy output observations.`);
