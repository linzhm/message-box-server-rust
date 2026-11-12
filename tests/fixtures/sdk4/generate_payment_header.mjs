// Generate offline vectors by executing the fixed upstream parser functions.
// This does not verify or make payments.
import {readFile, writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const evidence=JSON.parse(await readFile(process.env.TS_SERVER_EVIDENCE,'utf8'));
const entry=evidence.files['packages/middleware/payment-express-middleware/src/index.ts'];
const source=entry.content;
const bytes=Buffer.from(source,'utf8');
const sha=createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
assert.equal(sha,'c66270dafcc619b7d4f3de16d06e94ccbc143940');
const slice=(start,end)=>{const a=source.indexOf(start),b=source.indexOf(end,a);assert.ok(a>=0 && b>a);return source.slice(a,b);};
const fragment=slice('function isCanonicalBase64(', 'function isCompressedPublicKey(')+'\n'+slice('function parsePaymentHeader(', 'function parseAtomicPayment(')+'\nreturn parsePaymentHeader(raw);';
const ts=(await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
const compiled=ts.transpileModule(fragment,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const {toArray,toBase64}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/primitives/utils.ts`).href);
const upstream=new Function('raw','toArray','toBase64',compiled);
const good={derivationPrefix:'AA==',derivationSuffix:'AQ==',transaction:'Ag=='};
const cases=[
 JSON.stringify(good), JSON.stringify({...good,extra:{ignored:true}}),
 JSON.stringify({derivationPrefix:Buffer.alloc(48,1).toString('base64'),derivationSuffix:Buffer.alloc(48,2).toString('base64'),transaction:Buffer.from([0,1,2,253,254,255]).toString('base64')}),
 '{"derivationPrefix":"bad","derivationPrefix":"AA==","derivationSuffix":"AQ==","transaction":"Ag=="}',
 JSON.stringify({...good,derivationPrefix:''}), JSON.stringify({...good,derivationPrefix:'AB=='}),
 JSON.stringify({...good,derivationPrefix:'AA='}), JSON.stringify({...good,derivationPrefix:'AA'}),
 JSON.stringify({...good,derivationPrefix:'AA==\n'}), JSON.stringify({...good,derivationPrefix:'_w=='}),
 JSON.stringify({...good,derivationSuffix:null}), JSON.stringify({...good,transaction:12}),
 JSON.stringify({derivationPrefix:'AA==',derivationSuffix:'AQ=='}), '[]', 'null', '42', '{',
];
const vectors=cases.map(raw=>({raw,expected:upstream(raw,toArray,toBase64) ?? null}));
await writeFile(process.argv[2],JSON.stringify({sourceBlob:sha,vectors},null,2)+'\n');
console.log(`Generated ${vectors.length} fixed-source payment header vectors (offline; no payment).`);
