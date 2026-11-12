// Executes the pinned middleware's result-shape helper, without a wallet.
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const evidence=JSON.parse(await readFile(process.env.TS_SERVER_EVIDENCE,'utf8'));
const source=evidence.files['packages/middleware/payment-express-middleware/src/index.ts'].content,bytes=Buffer.from(source,'utf8');
assert.equal(createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex'),'c66270dafcc619b7d4f3de16d06e94ccbc143940');
const start=source.indexOf('function isNewlyAcceptedInternalization('),end=source.indexOf('function isPaymentLogger(',start);assert.ok(start>=0&&end>start);
const ts=(await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
const compiled=ts.transpileModule(source.slice(start,end)+'\nreturn isNewlyAcceptedInternalization(value);',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const sourceCheck=new Function('value',compiled);
const values=[null,[],{},true,{accepted:true},{accepted:true,isMerge:false},{accepted:true,isMerge:true},{accepted:true,isMerge:null},{accepted:false},{accepted:'true'},{accepted:1},{accepted:true,extra:'ignored'}];
const cases=values.map(value=>({value,expected:sourceCheck(value)}));
await writeFile(process.argv[2],JSON.stringify({sourceBlob:'c66270dafcc619b7d4f3de16d06e94ccbc143940',cases},null,2)+'\n');
console.log(`Generated ${cases.length} offline internalization result vectors.`);
