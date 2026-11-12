// Executes pinned allocation source on synthetic data, not payments.
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const evidence=JSON.parse(await readFile(process.env.TS_SERVER_EVIDENCE,'utf8'));
const source=evidence.files['infra/message-box-server/src/routes/sendMessage.ts'].content, bytes=Buffer.from(source);
const sha=createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
assert.equal(sha,'1279ce37c009e1cc37419824673f1ac4403b0510');
const a=source.indexOf('function taggedRecipient('),b=source.indexOf('async function prepareRecipientPayments(',a);assert.ok(a>=0&&b>a);
const ts=(await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
const js=ts.transpileModule(source.slice(a,b)+'\nreturn allocateTaggedRecipientOutputs(outputs,feeRecipients);',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const run=new Function('outputs','feeRecipients','routeFailure','routeValue',js);
const tag=recipientIdentityKey=>JSON.stringify({recipientIdentityKey});
const cases=[
 ['positional',{feeRecipients:['a','b'],outputs:[{outputIndex:0},{outputIndex:1}]}],
 ['too-few',{feeRecipients:['a','b'],outputs:[{outputIndex:0}]}],
 ['reordered-tags',{feeRecipients:['a','b'],outputs:[{outputIndex:0,customInstructions:tag('b')},{outputIndex:1,customInstructions:tag('a')}]}],
 ['mixed',{feeRecipients:['a','b'],outputs:[{outputIndex:0,customInstructions:tag('b')},{outputIndex:1}]}],
 ['unknown-tag-consumes',{feeRecipients:['a'],outputs:[{outputIndex:0,customInstructions:tag('other')}]}],
 ['multiple-tagged',{feeRecipients:['a'],outputs:[{outputIndex:0,customInstructions:tag('a')},{outputIndex:1,customInstructions:{recipientIdentityKey:'a'}}]}],
 ['malformed-is-untagged',{feeRecipients:['a'],outputs:[{outputIndex:0,customInstructions:'{bad'}]}],
 ['nullish-fallback',{feeRecipients:['a'],outputs:[{outputIndex:0,insertionRemittance:{customInstructions:null},paymentRemittance:{customInstructions:tag('a')}}]}],
 ['precedence',{feeRecipients:['a','b'],outputs:[{outputIndex:0,insertionRemittance:{customInstructions:tag('b')},paymentRemittance:{customInstructions:tag('a')}},{outputIndex:1}]}],
 ['nonempty-not-trimmed',{feeRecipients:['a'],outputs:[{outputIndex:0,customInstructions:tag(' a ')}]}],
 ['only-whitespace-is-untagged',{feeRecipients:['a'],outputs:[{outputIndex:0,customInstructions:tag('\u00a0\ufeff')}]}],
 ['duplicate-indices-reserved',{feeRecipients:['a','b'],outputs:[{outputIndex:0,customInstructions:tag('a')},{outputIndex:0},{outputIndex:1}]}]
];
const results=cases.map(([label,input])=>{const outputs=input.outputs;const result=run(outputs,input.feeRecipients,(_status,code)=>({error:code}),map=>({alloc:input.feeRecipients.map(recipient=>(map.get(recipient)??[]).map(o=>outputs.indexOf(o)))}));return {label,input,expected:result};});
await writeFile(process.argv[2],JSON.stringify({sourceBlob:sha,cases:results},null,2)+'\n');
console.log(`Generated ${results.length} allocation observations.`);
