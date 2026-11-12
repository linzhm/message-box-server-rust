// Executes fixed server health handlers using a synthetic Knex stub.
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const evidence=JSON.parse(await readFile(process.env.TS_SERVER_EVIDENCE,'utf8'));
let source=evidence.files['infra/message-box-server/src/routes/health.ts'].content;const bytes=Buffer.from(source);
const sha=createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');assert.equal(sha,'4705557d2b78a27f52ccf0ec507619df08df41fb');
source=source.replace(/^import .*$/gm,'').replaceAll('export const ','const ');
const ts=(await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
const js=ts.transpileModule(source+'\nreturn {healthRoute,healthzRoute,readinessRoute};',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
async function observe(route,fail=false){const runtimeDeps={knex:{raw:async(query)=>{assert.equal(query,'select 1');if(fail)throw new Error('synthetic database error');}}};const process={env:{BSV_NETWORK:'testnet',ENABLE_WEBSOCKETS:'false'}};const routes=new Function('runtimeDeps','process',js)(runtimeDeps,process);const result={headers:{}};const res={setHeader(k,v){result.headers[k.toLowerCase()]=v;},status(n){result.status=n;return this;},json(body){result.body=body;return this;}};await routes[route].func({},res);return result;}
const cases={health:await observe('healthRoute'),healthz:await observe('healthzRoute'),ready:await observe('readinessRoute'),notReady:await observe('readinessRoute',true)};
await writeFile(process.argv[2],JSON.stringify({sourceBlob:sha,cases},null,2)+'\n');console.log('Generated four health observations from fixed server handlers.');
