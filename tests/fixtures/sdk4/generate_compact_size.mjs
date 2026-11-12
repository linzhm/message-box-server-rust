// Compare the unsigned reader used by fixed SDK BEEF, without parsing BEEF.
import {pathToFileURL} from 'node:url';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
for (const [file,expected] of [['ReaderUint8Array.ts','e6b91eede8b83c8d7d31154a5ef353306fce0838'],['readVarIntNumStrict.ts','036532f653559be37cfcfb201985a9bba263b74a']]) {
 const data=await readFile(`${process.env.SDK_SOURCE_DIR}/src/primitives/${file}`);
 assert.equal(createHash('sha1').update(`blob ${data.length}\0`).update(data).digest('hex'),expected);
}
const {ReaderUint8Array}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/primitives/ReaderUint8Array.ts`));
const values=['','00','fc','fdfc00','fdfd00','fdffff','feffff0000','fe00000100','feffffffff','ffffffffff00000000','ff0000000001000000','ffffffffffffff1f00','ff0000000000002000','ffffffffffffffffff','fd','fd01','fe0000','ff0000000000','fdfd00aabb'];
const cases=values.map(hex=>{const r=new ReaderUint8Array(Uint8Array.from(Buffer.from(hex,'hex')));try{return {hex,expected:{value:r.readVarIntNumStrict(false),consumed:r.pos}};}catch{return {hex,expected:null};}});
await writeFile(process.argv[2],JSON.stringify({source:'SDK 4.0.1 @ ts-stack 52d36a5 ReaderUint8Array.readVarIntNumStrict(false)',cases},null,2)+'\n');
console.log(`Generated ${cases.length} offline unsigned CompactSize vectors.`);
