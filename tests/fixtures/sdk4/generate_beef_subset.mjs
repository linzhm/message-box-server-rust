// Synthetic, unfunded BEEF framing vectors. No payment or proof validation.
import {pathToFileURL} from 'node:url';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
for (const [file,expected] of [['Beef.ts','d71f285c27f264ead00d6f7a961e11139e96cb40'],['BeefTx.ts','90c94cd6ea2a07ae5db9408991db8637db56c60d'],['BeefConstants.ts','8f513cce2d23f766a4806bf4b7df231cbc71eb92']]) {
 const data=await readFile(`${process.env.SDK_SOURCE_DIR}/src/transaction/${file}`);
 assert.equal(createHash('sha1').update(`blob ${data.length}\0`).update(data).digest('hex'),expected);
}
const {default:Beef}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/transaction/Beef.ts`));
const raw='0100000000010100000000000000015100000000';
const id='cfe49d8f1ce145622642badc66cc70665a69a6cfc2376ef3499e2c8392001814';
const idWire=Buffer.from(id,'hex').reverse().toString('hex');
const atomic='01010101'+idWire, v1='0100beef',v2='0200beef';
const validV2=atomic+v2+'0001'+'00'+raw;
const cases=[
 {hex:validV2,supported:true},
 {hex:atomic+v1+'0001'+raw+'00',supported:true},
 {hex:atomic+v2+'0001'+'02'+idWire,supported:true},
 {hex:atomic+v2+'0000',supported:true},
 {hex:atomic+v2+'0002'+'00'+raw+'02'+idWire,supported:true},
 {hex:atomic+v2+'0002'+'00'+raw+'00'+raw,supported:true},
 {hex:'01010101'+'00'.repeat(32)+v2+'0001'+'00'+raw,supported:true},
 {hex:atomic+v1+'0001'+raw+'0100',supported:false},
 {hex:atomic+v2+'0001'+'01'+'00'+raw,supported:false},
 {hex:atomic+v2+'01'+'00'+'01'+'01'+'00'+'02'+idWire+'00',supported:false},
 {hex:validV2+'00',supported:true},
 {hex:v2+'0001'+'00'+raw,supported:false},
 {hex:atomic+v2+'0001'+'03'+raw,supported:false},
];
for(let i=0;i<validV2.length/2;i++)cases.push({hex:validV2.slice(0,i*2),supported:true});
const vectors=cases.map(({hex,supported})=>{try {
 const beef=Beef.fromBinaryStrict(Uint8Array.from(Buffer.from(hex,'hex')));
 const summary={atomicTxid:beef.atomicTxid??null,version:beef.version,entries:beef.txs.map(entry=>entry.isTxidOnly?{kind:'txid-only',txid:entry.txid}:{kind:'raw',txid:entry.txid,inputs:entry.tx.inputs.map(input=>input.sourceTXID),outputs:entry.tx.outputs.map(output=>({satoshis:output.satoshis,script:output.lockingScript.toHex()}))})};
 return {hex,sdkParsedAndInspected:true,expected:supported?summary:null};
} catch {return {hex,sdkParsedAndInspected:false,expected:null};}});
await writeFile(process.argv[2],JSON.stringify({source:'SDK 4.0.1 @ ts-stack 52d36a5 Beef.fromBinaryStrict plus inspected entries, synthetic/unfunded; limited subset',vectors},null,2)+'\n');
console.log(`Generated ${vectors.length} synthetic Atomic BEEF subset vectors.`);
