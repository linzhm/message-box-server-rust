// Synthetic BEEF/BUMP framing observations; no chain or payment validation.
import {pathToFileURL} from 'node:url';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
for (const [file,expected] of [['Beef.ts','d71f285c27f264ead00d6f7a961e11139e96cb40'],['BeefTx.ts','90c94cd6ea2a07ae5db9408991db8637db56c60d'],['MerklePath.ts','646253c784b03a5e821b55b748b471229edc4e3b']]) {
 const data=await readFile(`${process.env.SDK_SOURCE_DIR}/src/transaction/${file}`);
 assert.equal(createHash('sha1').update(`blob ${data.length}\0`).update(data).digest('hex'),expected);
}
const {default:Beef}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/transaction/Beef.ts`));
const {default:MerklePath}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/transaction/MerklePath.ts`));
const raw='0100000000010100000000000000015100000000',id='cfe49d8f1ce145622642badc66cc70665a69a6cfc2376ef3499e2c8392001814';
const idWire=Buffer.from(id,'hex').reverse().toString('hex');
const b='2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40';
const single=Buffer.from(new MerklePath(123,[[{offset:0,hash:id,txid:true}]],false).toBinary()).toString('hex');
const pair=Buffer.from(new MerklePath(124,[[{offset:0,hash:id,txid:true},{offset:1,hash:b}]],false).toBinary()).toString('hex');
const atom='01010101'+idWire,v1='0100beef',v2='0200beef';
const v2proof=atom+v2+'01'+single+'01'+'01'+'00'+raw;
const cases=[
 {hex:v2proof,supported:true},
 {hex:atom+v1+'01'+single+'01'+raw+'01'+'00',supported:true},
 {hex:atom+v2+'02'+single+pair+'01'+'01'+'01'+raw,supported:true},
 {hex:atom+v2+'01'+single+'01'+'01'+'01'+raw,supported:true}, // invalid index is structurally readable
 {hex:atom+v2+'00'+'01'+'00'+raw,supported:true},
 {hex:atom+v2+'01'+single+'01'+'02'+idWire,supported:true},
 {hex:atom+v1+'01'+single+'01'+raw+'02'+'00',supported:true}, // V1 nonzero marker

 {hex:v2proof+'00',supported:true},
];
const bad=Buffer.from(single,'hex');bad[3]=1; // single leaf offset 1
cases.push({hex:atom+v2+'01'+bad.toString('hex')+'01'+'01'+'00'+raw,supported:true});
for(let i=0;i<v2proof.length/2;i++)cases.push({hex:v2proof.slice(0,i*2),supported:true});
const vectors=cases.map(({hex,supported})=>{try {
 const beef=Beef.fromBinaryStrict(Uint8Array.from(Buffer.from(hex,'hex')));
 const summary={atomicTxid:beef.atomicTxid??null,version:beef.version,bumps:beef.bumps.map(bump=>({blockHeight:bump.blockHeight,leafTxid:bump.path[0].find(leaf=>leaf.txid===true)?.hash??null,root:bump.computeRoot()})),entries:beef.txs.map(entry=>entry.isTxidOnly?{kind:'txid-only',txid:entry.txid}:{kind:'raw',txid:entry.txid,bumpIndex:entry.bumpIndex??null})};
 return {hex,sdkParsedAndInspected:true,expected:supported?summary:null};
 }catch{return {hex,sdkParsedAndInspected:false,expected:null};}});
await writeFile(process.argv[2],JSON.stringify({source:'SDK 4.0.1 @ ts-stack 52d36a5 Beef.fromBinaryStrict with regular BUMPs, synthetic; structural only',vectors},null,2)+'\n');
console.log(`Generated ${vectors.length} synthetic BEEF/BUMP framing observations.`);
