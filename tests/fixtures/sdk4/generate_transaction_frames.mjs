// Synthetic, unfunded transactions. These are framing vectors, not payments.
import {pathToFileURL} from 'node:url';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
for (const [file,expected] of [['transaction/Transaction.ts','f1ac2509a152b48dd1dd4ba5d34e4df1bc3fdfef'],['script/Script.ts','8b0570872ce87f7c0648a827dcf5ae32828fdbc5']]) {
 const data=await readFile(`${process.env.SDK_SOURCE_DIR}/src/${file}`);
 assert.equal(createHash('sha1').update(`blob ${data.length}\0`).update(data).digest('hex'),expected);
}
const {default:Transaction}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/transaction/Transaction.ts`));
const version='01000000', lock='00000000';
const output='01000000000000000151';
const simple=version+'00'+'01'+output+lock;
const input=Array.from({length:32},(_,i)=>i.toString(16).padStart(2,'0')).join('')+'02000000'+'01'+'51'+'ffffffff';
const secondOutput='2a00000000000000026a00';
const withInput=version+'01'+input+'02'+output+secondOutput+lock;
const unsafe=version+'00'+'01'+'0000000000002000'+'0151'+lock;
const malformedPush=version+'00'+'01'+'0100000000000000'+'014c'+lock;
const largeScript=version+'00'+'01'+'0100000000000000'+'fdfd00'+'51'.repeat(253)+lock;
const noncanonicalScript=version+'00'+'01'+'0100000000000000'+'fdfc00'+'51'.repeat(252)+lock;
const maxAmount=version+'00'+'01'+'ffffffffffff1f00'+'0151'+lock;
const empty=version+'00'+'00'+lock;
const cases=[simple,withInput,malformedPush,unsafe,simple+'00',version+'fdfc00',version+'feffff0000',largeScript,noncanonicalScript,maxAmount,empty];
for(let i=0;i<simple.length/2;i++)cases.push(simple.slice(0,i*2));
const vectors=cases.map(hex=>{try {const tx=Transaction.fromBinary(Uint8Array.from(Buffer.from(hex,'hex')));return {hex,expected:{txid:tx.id('hex'),inputs:tx.inputs.map(input=>input.sourceTXID),outputs:tx.outputs.map(output=>({satoshis:output.satoshis,script:output.lockingScript.toHex()}))}};} catch {return {hex,expected:null};}});
await writeFile(process.argv[2],JSON.stringify({source:'SDK 4.0.1 @ ts-stack 52d36a5 Transaction.fromBinary, synthetic/unfunded',vectors},null,2)+'\n');
console.log(`Generated ${vectors.length} synthetic transaction framing vectors.`);
