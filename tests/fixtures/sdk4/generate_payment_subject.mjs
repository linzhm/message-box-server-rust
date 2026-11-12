// Offline fixed-middleware subject-output observations. All BEEF inputs are
// synthetic and unfunded. This does not verify or internalize payments.
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const evidence=JSON.parse(await readFile(process.env.TS_SERVER_EVIDENCE,'utf8'));
const entry=evidence.files['packages/middleware/payment-express-middleware/src/index.ts'];
const source=entry.content, bytes=Buffer.from(source,'utf8');
assert.equal(createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex'),'c66270dafcc619b7d4f3de16d06e94ccbc143940');
const start=source.indexOf('function parseAtomicPayment('),end=source.indexOf('function sendError(',start);
assert.ok(start>=0 && end>start);
const ts=(await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
const compiled=ts.transpileModule(source.slice(start,end)+'\nreturn parseAtomicPayment(payment,price);',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const {default:Beef}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/transaction/Beef.ts`));
const {toArray}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/primitives/utils.ts`));
const upstream=new Function('payment','price','Beef','toArray',compiled);
const input=JSON.parse(await readFile(process.argv[2],'utf8'));
const cases=input.vectors.map(v=>({hex:v.hex,subsetSupported:v.expected!==null,price:1}));
for(const [label,amounts] of [['amount-under',[99]],['amount-exact',[100]],['amount-first-under',[99,1]],['no-outputs',[]]]) {
 const outputs=amounts.map(amount=>{const n=Buffer.alloc(8);n.writeBigUInt64LE(BigInt(amount));return n.toString('hex')+'0151';}).join('');
 const raw='0100000000'+amounts.length.toString(16).padStart(2,'0')+outputs+'00000000';
 const first=createHash('sha256').update(Buffer.from(raw,'hex')).digest();
 const idWire=createHash('sha256').update(first).digest('hex');
 cases.push({label,hex:'01010101'+idWire+'0200beef000100'+raw,subsetSupported:true,price:100});
}
// Unfunded synthetic parent/child graph. A zero-input parent cannot establish
// spendability or any chain proof; these only exercise subject selection.
const hashWire=raw=>createHash('sha256').update(createHash('sha256').update(Buffer.from(raw,'hex')).digest()).digest('hex');
const output=amount=>{const n=Buffer.alloc(8);n.writeBigUInt64LE(BigInt(amount));return n.toString('hex')+'0151';};
const parent='010000000001'+output(101)+'00000000', parentWire=hashWire(parent);
const child='0100000001'+parentWire+'0000000000ffffffff01'+output(100)+'00000000',childWire=hashWire(child);
const unrelated='010000000001'+output(1000)+'00000000';
const unrelatedWire=hashWire(unrelated);
const spend=wire=>wire+'0000000000ffffffff';
const middle='0100000001'+spend(parentWire)+'01'+output(102)+'00000000',middleWire=hashWire(middle);
const grandchild='0100000001'+spend(middleWire)+'01'+output(100)+'00000000',grandchildWire=hashWire(grandchild);
const branched='0100000002'+spend(parentWire)+spend(unrelatedWire)+'01'+output(100)+'00000000',branchedWire=hashWire(branched);
const atomicFor=(subject,entries)=>'01010101'+subject+'0200beef00'+entries.length.toString(16).padStart(2,'0')+entries.join('');
cases.push({label:'long-chain',hex:atomicFor(grandchildWire,['00'+grandchild,'00'+parent,'00'+middle]),subsetSupported:true,price:100});
cases.push({label:'branch-unsupported',hex:atomicFor(branchedWire,['00'+parent,'00'+unrelated,'00'+branched]),subsetSupported:true,price:100});
cases.push({label:'branch-reversed',hex:atomicFor(branchedWire,['00'+branched,'00'+unrelated,'00'+parent]),subsetSupported:true,price:100});
const atomicV1=(subject,raws)=>'01010101'+subject+'0100beef00'+raws.length.toString(16).padStart(2,'0')+raws.map(raw=>raw+'00').join('');
cases.push({label:'branch-v1-reversed',hex:atomicV1(branchedWire,[branched,unrelated,parent]),subsetSupported:true,price:100});
const orphan='0100000001'+spend('22'.repeat(32))+'01'+output(500)+'00000000';
cases.push({label:'orphan-unrelated',hex:atomicFor(parentWire,['00'+orphan,'00'+parent]),subsetSupported:true,price:100});


cases.push({label:'branch-known-parent',hex:atomicFor(branchedWire,['00'+branched,'02'+parentWire,'00'+unrelated]),subsetSupported:true,price:100});
const left='0100000001'+spend(parentWire)+'01'+output(40)+'00000000',leftWire=hashWire(left);
const right='0100000001'+spend(unrelatedWire)+'01'+output(60)+'00000000',rightWire=hashWire(right);
const diamond='0100000002'+spend(leftWire)+spend(rightWire)+'01'+output(100)+'00000000',diamondWire=hashWire(diamond);
cases.push({label:'fork-join-shuffled',hex:atomicFor(diamondWire,['00'+right,'00'+parent,'00'+diamond,'00'+left,'00'+unrelated]),subsetSupported:true,price:100});
const rightShared='0100000001'+spend(parentWire)+'01'+output(60)+'00000000',rightSharedWire=hashWire(rightShared);
const shared='0100000002'+spend(leftWire)+spend(rightSharedWire)+'01'+output(100)+'00000000',sharedWire=hashWire(shared);
cases.push({label:'diamond-shared',hex:atomicFor(sharedWire,['00'+rightShared,'00'+parent,'00'+shared,'00'+left]),subsetSupported:true,price:100});
const sameParentSecond=parentWire+'0100000000ffffffff';
const repeated='0100000002'+spend(parentWire)+sameParentSecond+'01'+output(100)+'00000000',repeatedWire=hashWire(repeated);
cases.push({label:'duplicate-parent-inputs',hex:atomicFor(repeatedWire,['00'+repeated,'00'+parent]),subsetSupported:true,price:100});



const atomic=entries=>'01010101'+childWire+'0200beef00'+entries.length.toString(16).padStart(2,'0')+entries.join('');
for(const [label,entries] of [
 ['unrelated',['00'+unrelated,'00'+parent,'00'+child]],
 ['missing-parent',['00'+child]],
 ['reordered-parent-child',['00'+child,'00'+parent]],
 ['txid-only-parent',['02'+parentWire,'00'+child]],
 ['duplicate-last-id',['00'+child,'02'+childWire]],
 ['duplicate-last-raw',['02'+childWire,'00'+child]],
]) cases.push({label,hex:atomic(entries),subsetSupported:true,price:100});
const vectors=cases.map(v=>{const payment={derivationPrefix:'AA==',derivationSuffix:'AQ==',transaction:Buffer.from(v.hex,'hex').toString('base64')};
 const parsed=upstream(payment,v.price,Beef,toArray);let sdkVerifyValid=null;
 if(v.label){try{sdkVerifyValid=Beef.fromBinaryStrict(Buffer.from(v.hex,'hex')).verifyValid().valid;}catch{}}
 return {...v,sdkVerifyValid,expected:parsed==null?null:{txid:parsed.transactionId,satoshis:parsed.satoshis},normalizedTxids:parsed==null?null:Beef.fromBinaryStrict(parsed.transaction).txs.map(tx=>tx.txid),normalizedHex:parsed==null?null:Buffer.from(parsed.transaction).toString('hex')};});
await writeFile(process.argv[3],JSON.stringify({sourceBlob:'c66270dafcc619b7d4f3de16d06e94ccbc143940',vectors},null,2)+'\n');
console.log(`Generated ${vectors.length} offline synthetic subject observations.`);
