// Synthetic Merkle paths, no block or chain connection.
import {pathToFileURL} from 'node:url';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const file=`${process.env.SDK_SOURCE_DIR}/src/transaction/MerklePath.ts`, data=await readFile(file);
assert.equal(createHash('sha1').update(`blob ${data.length}\0`).update(data).digest('hex'),'646253c784b03a5e821b55b748b471229edc4e3b');
const {default:MerklePath}=await import(pathToFileURL(file));
const {ReaderUint8Array}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/primitives/ReaderUint8Array.ts`));
const hash=(start)=>Array.from({length:32},(_,i)=>(i+start).toString(16).padStart(2,'0')).join('');
const a=hash(1), b=hash(33), c=hash(65);
const path=(levels)=>Buffer.from(new MerklePath(123,levels,false).toBinary()).toString('hex');
const single=path([[{offset:0,hash:a,txid:true}]]);
const extraFlag=Buffer.from(single,'hex');extraFlag[4]=6;
const pair=path([[{offset:0,hash:a,txid:true},{offset:1,hash:b}]]);
const changedPair=Buffer.from(pair,'hex');changedPair[changedPair.length-1]^=1;
const two=path([[{offset:0,hash:a,txid:true},{offset:1,hash:b}],[{offset:1,hash:c}]]);
const odd=path([[{offset:2,hash:a,txid:true},{offset:3,hash:b}],[{offset:0,hash:c}]]);
const compound=path([[{offset:0,hash:a,txid:true},{offset:1,hash:b,txid:true}]]);
const pairOdd=path([[{offset:0,hash:b},{offset:1,hash:a,txid:true}]]);
const twoOdd=path([[{offset:2,hash:b},{offset:3,hash:a,txid:true}],[{offset:0,hash:c}]]);
const deep=path([[{offset:0,hash:a,txid:true},{offset:1,hash:b}],...Array.from({length:19},()=>[{offset:1,hash:c}])]);
const maxDepth=path([[{offset:0,hash:a,txid:true},{offset:1,hash:b}],...Array.from({length:53},()=>[{offset:1,hash:c}])]);
const duplicate=path([[{offset:0,hash:a,txid:true},{offset:1,duplicate:true}]]);

const badOffset='00'+'01'+'01'+'01'+'02'+Buffer.from(a,'hex').reverse().toString('hex');
const cases=[{hex:single,supported:true},{hex:extraFlag.toString('hex'),supported:false},{hex:pair,supported:true},{hex:changedPair.toString('hex'),supported:true},{hex:two,supported:true},{hex:odd,supported:true},{hex:pairOdd,supported:true},{hex:twoOdd,supported:true},{hex:deep,supported:true},{hex:maxDepth,supported:true},{hex:duplicate,supported:false},{hex:compound,supported:false},{hex:badOffset,supported:true},{hex:two+'00',supported:true}];
for(let i=0;i<two.length/2;i++)cases.push({hex:two.slice(0,i*2),supported:true});
const vectors=cases.map(({hex,supported})=>{try {
 const bytes=Uint8Array.from(Buffer.from(hex,'hex')),reader=new ReaderUint8Array(bytes);
 const bump=MerklePath.fromReader(reader,false);if(reader.pos!==bytes.length)throw new Error('trailing');
 const leaf=bump.path[0].find(entry=>entry.txid===true);
 if(!leaf?.hash)throw new Error('no anchor');
 return {hex,sdkParsedAndInspected:true,expected:supported?{blockHeight:bump.blockHeight,leafTxid:leaf.hash,root:bump.computeRoot(leaf.hash)}:null};
 } catch {return {hex,sdkParsedAndInspected:false,expected:null};}});
await writeFile(process.argv[2],JSON.stringify({source:'SDK 4.0.1 @ ts-stack 52d36a5 MerklePath.fromReader(false), synthetic; exact framing, restricted regular paths',vectors},null,2)+'\n');
console.log(`Generated ${vectors.length} synthetic regular BUMP observations.`);
