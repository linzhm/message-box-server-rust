// Synthetic unfunded BUMP/BEEF normalization observations. No chain or payment.
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const evidence=JSON.parse(await readFile(process.env.TS_SERVER_EVIDENCE,'utf8'));
const entry=evidence.files['packages/middleware/payment-express-middleware/src/index.ts'];
const source=entry.content, bytes=Buffer.from(source,'utf8');
assert.equal(createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex'),'c66270dafcc619b7d4f3de16d06e94ccbc143940');
const start=source.indexOf('function parseAtomicPayment('),end=source.indexOf('function sendError(',start);assert.ok(start>=0&&end>start);
const ts=(await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
const compiled=ts.transpileModule(source.slice(start,end)+'\nreturn parseAtomicPayment(payment,price);',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const {default:Beef}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/transaction/Beef.ts`));
const {default:MerklePath}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/transaction/MerklePath.ts`));
const {toArray}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/primitives/utils.ts`));
const upstream=new Function('payment','price','Beef','toArray',compiled);
const hashWire=raw=>createHash('sha256').update(createHash('sha256').update(Buffer.from(raw,'hex')).digest()).digest('hex');
const display=wire=>Buffer.from(wire,'hex').reverse().toString('hex');
const output=amount=>{const n=Buffer.alloc(8);n.writeBigUInt64LE(BigInt(amount));return n.toString('hex')+'0151';};
const spend=wire=>wire+'0000000000ffffffff';
const parent='010000000001'+output(101)+'00000000',parentWire=hashWire(parent),parentId=display(parentWire);
const child='0100000001'+spend(parentWire)+'01'+output(100)+'00000000',childWire=hashWire(child),childId=display(childWire);
const missing='0100000001'+spend('22'.repeat(32))+'01'+output(100)+'00000000',missingWire=hashWire(missing),missingId=display(missingWire);
const other='11'.repeat(32);
const bump=(height,levels)=>Buffer.from(new MerklePath(height,levels,false).toBinary()).toString('hex');
const single=bump(123,[[{offset:0,hash:childId,txid:true}]]);
const parentBump=bump(123,[[{offset:0,hash:parentId,txid:true}]]);
const missingBump=bump(123,[[{offset:0,hash:missingId,txid:true}]]);
const unrelated=bump(124,[[{offset:0,hash:other,txid:true}]]);
const unflagged=bump(125,[[{offset:0,hash:other,txid:true},{offset:1,hash:childId}]]);
const otherRaw='010000000001'+output(102)+'00000000',otherWire=hashWire(otherRaw),otherId=display(otherWire);
const otherBump=bump(126,[[{offset:0,hash:otherId,txid:true}]]);
const merge='0100000002'+spend(parentWire)+spend(otherWire)+'01'+output(100)+'00000000',mergeWire=hashWire(merge);
const sharedBump=bump(127,[[{offset:0,hash:parentId,txid:true},{offset:1,hash:otherId}]]);

const swapped=Buffer.from(unflagged,'hex');const left=Buffer.from(swapped.subarray(3,37));const right=Buffer.from(swapped.subarray(37,71));right.copy(swapped,3);left.copy(swapped,37);
const wrap=(id,version,bumps,entries)=>'01010101'+id+version+bumps.length.toString(16).padStart(2,'0')+bumps.join('')+entries.length.toString(16).padStart(2,'0')+entries.join('');
const cases=[
 ['v2-proof',wrap(childWire,'0200beef',[single],['0100'+child])],
 ['v1-proof',wrap(childWire,'0100beef',[single],[child+'0100'])],
 ['v1-nonzero-marker',wrap(childWire,'0100beef',[single],[child+'0200'])],
 ['unused-unsorted',wrap(childWire,'0200beef',[swapped.toString('hex'),single],['0101'+child])],

 ['remap-unused',wrap(childWire,'0200beef',[unrelated,single],['0101'+child])],
 ['unflagged-subject',wrap(childWire,'0200beef',[unflagged],['0100'+child])],
 ['proof-stops-missing-parent',wrap(missingWire,'0200beef',[missingBump],['0100'+missing])],
 ['parent-proof-child',wrap(childWire,'0200beef',[parentBump],['00'+child,'0100'+parent])],
 ['two-proof-remap',wrap(mergeWire,'0200beef',[otherBump,parentBump],['00'+merge,'0101'+parent,'0100'+otherRaw])],
 ['known-and-proof',wrap(mergeWire,'0200beef',[otherBump],['00'+merge,'02'+parentWire,'0100'+otherRaw])],
 ['shared-bump',wrap(mergeWire,'0200beef',[sharedBump],['00'+merge,'0100'+parent,'0100'+otherRaw])],

 ['invalid-index',wrap(childWire,'0200beef',[single],['0101'+child])],
 ['unsorted-bump',wrap(childWire,'0200beef',[swapped.toString('hex')],['0100'+child])],
 ['unmatched-leaf',wrap(childWire,'0200beef',[unrelated],['0100'+child])],
];
const vectors=cases.map(([label,hex])=>{const payment={derivationPrefix:'AA==',derivationSuffix:'AQ==',transaction:Buffer.from(hex,'hex').toString('base64')};const parsed=upstream(payment,1,Beef,toArray);return {label,hex,expected:parsed==null?null:{txid:parsed.transactionId,satoshis:parsed.satoshis,normalizedHex:Buffer.from(parsed.transaction).toString('hex')}};});
await writeFile(process.argv[2],JSON.stringify({sourceBlob:'c66270dafcc619b7d4f3de16d06e94ccbc143940',vectors},null,2)+'\n');
console.log(`Generated ${vectors.length} offline synthetic BUMP-payment observations.`);
