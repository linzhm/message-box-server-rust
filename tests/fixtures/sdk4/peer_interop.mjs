// Local stdio interoperability against fixed SDK source. Test keys only.
// This is not HTTP and does not prove binding a real request frame.
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {pathToFileURL} from 'node:url';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import assert from 'node:assert/strict';
const root=process.env.SDK_SOURCE_DIR;
const {Peer}=await import(pathToFileURL(`${root}/src/auth/Peer.ts`));
const {default:ProtoWallet}=await import(pathToFileURL(`${root}/src/wallet/ProtoWallet.ts`));
const {default:PrivateKey}=await import(pathToFileURL(`${root}/src/primitives/PrivateKey.ts`));
const {Writer,toArray}=await import(pathToFileURL(`${root}/src/primitives/utils.ts`));
const dir=await mkdtemp(join(tmpdir(),'messagebox-auth-fixture-'));
function startBridge(db) {
 const child=spawn(process.env.AUTH_PEER_FIXTURE,[],{stdio:['pipe','pipe','inherit'],env:{...process.env,AUTH_TEST_DB:db}});
 const incoming=createInterface({input:child.stdout})[Symbol.asyncIterator]();
 return {
  async exchange(message){child.stdin.write(`${JSON.stringify(message)}\n`);const line=await incoming.next();if(line.done)throw new Error('test bridge exited');return JSON.parse(line.value);},
  async close(){child.stdin.end();await new Promise((resolve,reject)=>child.once('exit',code=>code===0?resolve():reject(new Error(`bridge exited ${code}`))));}
 };
}
try {
 const db=join(dir,'auth.sqlite');const bridge=startBridge(db);let onData,general,verified,signedResponse,received;
 const transport={
  async onData(callback){onData=callback;},
  async send(message){
   const result=await bridge.exchange(message);assert.equal(result.ok,true,JSON.stringify(result));
   if(message.messageType==='initialRequest')await onData(result.message);
   else if(message.messageType==='general'){general=message;verified=result;signedResponse=result.message;await onData(result.message);}
   else throw new Error(`unexpected message type ${message.messageType}`);
  }
 };
 const clientKey=new PrivateKey(2),serverKey=new PrivateKey(3);
 const peer=new Peer(new ProtoWallet(clientKey),transport);
 peer.listenForGeneralMessages((identity,bytes)=>{received={identity,bytes};});await peer.ready;
 const payload=[...Array.from({length:32},(_,i)=>i),1,2,3,4,255];await peer.toPeer(payload,serverKey.toPublicKey().toString());
 assert.equal(verified.identity,clientKey.toPublicKey().toString());assert.deepEqual(verified.payload,payload);
 const expected=new Writer();expected.write(payload.slice(0,32));expected.writeVarIntNum(200);expected.writeVarIntNum(1);
 for(const v of ['x-bsv-extra','ok']){const bytes=toArray(v,'utf8');expected.writeVarIntNum(bytes.length);expected.write(bytes);}
 const body=toArray('hello','utf8');expected.writeVarIntNum(body.length);expected.write(body);
 assert.equal(received.identity,serverKey.toPublicKey().toString());assert.deepEqual(received.bytes,expected.toArray());
 const badResponse={...signedResponse,payload:[...signedResponse.payload]};badResponse.payload[35]^=1;
 await assert.rejects(onData(badResponse),/signature/i);
 await assert.rejects(onData(signedResponse),/replay/i);
 const tamperedPayload=[...payload];tamperedPayload[33]^=1;
 const tampered=await bridge.exchange({...general,payload:tamperedPayload});assert.equal(tampered.ok,false);assert.equal(tampered.error,'InvalidProof');
 const wrongIdentity=await bridge.exchange({...general,identityKey:new PrivateKey(4).toPublicKey().toString()});assert.equal(wrongIdentity.ok,false);assert.equal(wrongIdentity.error,'IdentityMismatch');
 const replay=await bridge.exchange(general);assert.equal(replay.ok,false);assert.equal(replay.error,'Replay');
 await bridge.close();
 const restarted=startBridge(db);const replayAfterRestart=await restarted.exchange(general);assert.equal(replayAfterRestart.ok,false);assert.equal(replayAfterRestart.error,'Replay');await restarted.close();
 async function expectHandshakeFailure(target,certificates,pattern,name) {
  const child=startBridge(join(dir,`${name}.sqlite`));let callback,sawGeneral=false;
  const t={async onData(cb){callback=cb;},async send(message){if(message.messageType==='general')sawGeneral=true;const result=await child.exchange(message);if(!result.ok)throw new Error(result.error);if(message.messageType==='initialRequest')await callback(result.message);}};
  const p=new Peer(new ProtoWallet(clientKey),t,certificates);await p.ready;
  await assert.rejects(p.toPeer(payload,target),pattern);assert.equal(sawGeneral,false);await child.close();
 }
 await expectHandshakeFailure(new PrivateKey(4).toPublicKey().toString(),undefined,/identity does not match/,'wrong-server');
 await expectHandshakeFailure(serverKey.toPublicKey().toString(),{certifiers:[new PrivateKey(4).toPublicKey().toString()],types:{}},/UnsupportedCertificates/,'certificates');
 console.log('Fixed SDK Peer and Rust responder: no-certificate handshake, signed request and response, tamper, identity, replay after process restart, wrong server and unsupported certificates passed over test-only stdio and local SQLite.');
} finally {await rm(dir,{recursive:true,force:true});}
