// Executes the pinned server AuthSocket payload codec, with synthetic data.
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const path=`${process.env.AUTHSOCKET_SOURCE_DIR}/packages/messaging/authsocket/src/eventPayload.ts`;
const bytes=await readFile(path),blob=createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');assert.equal(blob,'802dc0e77555a493cc4953c4fff28dbde14f1ecc');
const {encodeAuthSocketEventPayload:encode,parseAuthSocketEventPayload:parse}=await import(pathToFileURL(path));
let nested='x';for(let i=0;i<65;i++)nested=[nested];
let depth63='x',depth64='x';for(let i=0;i<63;i++)depth63=[depth63];for(let i=0;i<64;i++)depth64=[depth64];
const inputs=[
 {label:'missing',eventName:'joinRoom',hasData:false},
 {label:'null',eventName:'joinRoom',hasData:true,data:null},
 {label:'string',eventName:'joinRoom',hasData:true,data:'room-猫'},
 {label:'object',eventName:'message',hasData:true,data:{z:'猫',a:[true,null,42,-3]}},
 {label:'escapes',eventName:'notice',hasData:true,data:'\u0000\b\f\n\r\t"\\\u2028😀'},
 {label:'safe-maximum',eventName:'n',hasData:true,data:9007199254740991},
 {label:'float-source-valid',eventName:'n',hasData:true,data:1.5},
 {label:'numeric-key-source-valid',eventName:'n',hasData:true,data:{'1':'numeric'}},
 {label:'reserved',eventName:'connect',hasData:false},
 {label:'control-name',eventName:'a\u0000b',hasData:false},
 {label:'bidi-name',eventName:'a\u202eb',hasData:false},
 {label:'too-long-name',eventName:'a'.repeat(257),hasData:false},
 {label:'unsafe-key',eventName:'n',hasData:true,data:JSON.parse('{"__proto__":1}')},
 {label:'depth-63',eventName:'n',hasData:true,data:depth63},
 {label:'depth-64',eventName:'n',hasData:true,data:depth64},
 {label:'too-deep',eventName:'n',hasData:true,data:nested},
 {label:'estimated-limit',eventName:'n',hasData:false,max:14},
 {label:'wire-limit',eventName:'n',hasData:false,max:16},
 {label:'byte-limit',eventName:'abc',hasData:true,data:'x'.repeat(100),max:32}
];
const cases=inputs.map(input=>{let encoded=null,decoded=null,error=false;try{const payload=encode(input.eventName,input.hasData?input.data:undefined,input.max??1048576);encoded=Buffer.from(payload).toString('hex');const result=parse(payload,input.max??1048576);decoded={eventName:result.eventName,...(result.data===undefined?{}:{data:result.data})};}catch{error=true;}return {input,encoded,decoded,error};});
const rawInputs=[
 {label:'space-order',hex:Buffer.from(' { "data":null, "eventName":"joinRoom" } ').toString('hex')},
 {label:'bom',hex:'efbbbf'+Buffer.from('{"eventName":"joinRoom"}').toString('hex')},
 {label:'duplicate',hex:Buffer.from('{"eventName":"bad","eventName":"joinRoom","data":null}').toString('hex')},
 {label:'invalid-utf8',hex:'ff'},
 {label:'extra-key',hex:Buffer.from('{"eventName":"joinRoom","other":1}').toString('hex')}
];
const rawCases=rawInputs.map(input=>{let decoded=null,error=false;try{const result=parse([...Buffer.from(input.hex,'hex')],1048576);decoded={eventName:result.eventName,...(result.data===undefined?{}:{data:result.data})};}catch{error=true;}return {input,decoded,error};});
const countCases=[99997,99998].map(count=>{try{encode('n',Array(count).fill(null),1048576);return {count,error:false};}catch{return {count,error:true};}});
await writeFile(process.argv[2],JSON.stringify({sourceBlob:blob,cases,rawCases,countCases},null,2)+'\n');console.log(`Generated ${cases.length} encode and ${rawCases.length} parse observations.`);
