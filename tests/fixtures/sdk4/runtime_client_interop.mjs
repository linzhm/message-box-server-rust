// Fixed SDK/MessageBoxClient against the real loopback-only runtime.
// Public test keys, disposable database, no payment or WebSocket.
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {pathToFileURL} from 'node:url';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {once} from 'node:events';
import assert from 'node:assert/strict';
const nativeFetch=globalThis.fetch;let handshakes=0;
globalThis.fetch=(url,options)=>{if(String(url).includes('/.well-known/auth')) handshakes++;return nativeFetch(url,options);};
const sdk=process.env.SDK_SOURCE_DIR,clientSource=process.env.CLIENT_SOURCE_DIR;
const {MessageBoxClient}=await import(pathToFileURL(`${clientSource}/packages/messaging/message-box-client/src/MessageBoxClient.ts`));
const {AuthFetch}=await import(pathToFileURL(`${sdk}/src/auth/clients/AuthFetch.ts`));
const {default:ProtoWallet}=await import(pathToFileURL(`${sdk}/src/wallet/ProtoWallet.ts`));
const {default:PrivateKey}=await import(pathToFileURL(`${sdk}/src/primitives/PrivateKey.ts`));
const dir=await mkdtemp(join(tmpdir(),'messagebox-runtime-interop-'));
const keyFile=join(dir,'identity.key'),configFile=join(dir,'config.json');
await writeFile(keyFile,'0'.repeat(63)+'3\n',{mode:0o600});
await writeFile(configFile,JSON.stringify({bind:'127.0.0.1:0',dataDir:dir,identityKeyFile:keyFile,freeBoxes:['inbox']}));
let child;
async function start(){
 child=spawn(process.env.MESSAGEBOX_SERVER,[configFile],{stdio:['ignore','pipe','inherit'],env:{...process.env,BSV_NETWORK:'testnet'}});
 const exited=once(child,'exit').then(([code,signal])=>({earlyExit:{code,signal}}));
 const line=createInterface({input:child.stdout})[Symbol.asyncIterator]();
 const ready=await Promise.race([line.next(),exited,new Promise((_,reject)=>setTimeout(()=>reject(new Error('runtime startup timeout')),10000))]);
 assert.ok(!ready.earlyExit,`early exit: ${JSON.stringify(ready.earlyExit)}`);
 const value=JSON.parse(ready.value);assert.equal(value.status,'ready');
 return value;
}
async function stop(){const exited=once(child,'exit');child.kill('SIGINT');const [code,signal]=await exited;assert.equal(code,0,`runtime exit ${code}/${signal}`);child=undefined;}
function wallet(n){const result=new ProtoWallet(new PrivateKey(n));result.createAction=async()=>{throw new Error('Payment disabled in test');};return result;}
function client(host,walletClient,server){return new MessageBoxClient({host,walletClient,serverIdentityKeysByHost:{[host]:server}});}
try{
 let ready=await start();const expected=new PrivateKey(3).toPublicKey().toString();assert.equal(ready.identityKey,expected);
 let host=`http://${ready.address}`;const alice=wallet(2),bob=wallet(4),bobId=new PrivateKey(4).toPublicKey().toString(),aliceId=new PrivateKey(2).toPublicKey().toString();
 let sender=client(host,alice,expected),receiver=client(host,bob,expected);
 let healthLength=0;
 for(const path of ['/health','/healthz']){const response=await fetch(`${host}${path}?probe=1`);assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-store');const body=await response.text();assert.deepEqual(JSON.parse(body),{ok:true,status:'ok',service:'messagebox-server',network:'testnet',websockets:false});if(path==='/health')healthLength=Buffer.byteLength(body);}
 const head=await fetch(`${host}/health`,{method:'HEAD'});assert.equal(head.status,200);assert.equal(head.headers.get('cache-control'),'no-store');assert.equal(await head.text(),'');assert.equal(Number(head.headers.get('content-length')),healthLength);
 const readiness=await fetch(`${host}/ready`);assert.equal(readiness.status,200);assert.equal(readiness.headers.get('cache-control'),'no-store');const readyBody=await readiness.text();assert.deepEqual(JSON.parse(readyBody),{status:'ready'});
 for(const [path,length] of [['/healthz',healthLength],['/ready',Buffer.byteLength(readyBody)]]){const response=await fetch(`${host}${path}`,{method:'HEAD'});assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-store');assert.equal(await response.text(),'');assert.equal(Number(response.headers.get('content-length')),length);}
 const malformed=await fetch(`${host}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:'{'});assert.equal(malformed.status,400);assert.deepEqual(await malformed.json(),{status:'error',code:'ERR_INVALID_BODY',description:'The request body is invalid.'});
 assert.equal((await fetch(`${host}/devices`)).status,401);
 const auth=new AuthFetch(alice,undefined,undefined,undefined,{responseTimeoutMs:3000});
 const signed=await auth.fetch(`${host}/devices`,{method:'GET',requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false});assert.equal(signed.status,200);
 const orderedList=await auth.fetch(`${host}/listMessages`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({offset:0,messageBox:'inbox'}),requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false});assert.equal(orderedList.status,200);
 const slashList=await auth.fetch(`${host}//listMessages`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({messageBox:'inbox'}),requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false});assert.equal(slashList.status,200);
 const tripleList=await auth.fetch(`${host}///listMessages`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({messageBox:'inbox'}),requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false});assert.equal(tripleList.status,200);
 const slashGet=await auth.fetch(`${host}//devices?limit=1`,{method:'GET',requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false});assert.equal(slashGet.status,200);assert.equal((await fetch(`${host}//health`)).status,200);assert.equal((await fetch(`${host}//health`,{method:'HEAD'})).status,200);
 let rewrittenHandshake=false;const handshakeSlash=async(url,init)=>{if(String(url).endsWith('/.well-known/auth')){rewrittenHandshake=true;return fetch(String(url).replace('/.well-known/auth','//.well-known/auth'),init)}return fetch(url,init)};const slashHandshake=new AuthFetch(wallet(5),undefined,undefined,undefined,{responseTimeoutMs:3000},handshakeSlash);
 const handshakeResult=await slashHandshake.fetch(`${host}/devices`,{method:'GET',requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false});assert.equal(handshakeResult.status,200);assert.equal(rewrittenHandshake,true);
 let slashTamperStatus;const mutateSlash=async(url,init)=>{const headers=new Headers(init.headers);if(String(url).endsWith('/listMessages')&&headers.has('x-bsv-auth-request-id')){const response=await fetch(String(url).replace('/listMessages','//listMessages'),init);slashTamperStatus=response.status;return response;}return fetch(url,init)};const tamperedSlash=new AuthFetch(alice,undefined,undefined,undefined,{responseTimeoutMs:1500},mutateSlash);
 await assert.rejects(tamperedSlash.fetch(`${host}/listMessages`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({messageBox:'inbox'}),requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false}));assert.equal(slashTamperStatus,401);
 let tripleTamperStatus;const mutateTriple=async(url,init)=>{const headers=new Headers(init.headers);if(String(url).endsWith('/listMessages')&&headers.has('x-bsv-auth-request-id')){const response=await fetch(String(url).replace('//listMessages','///listMessages'),init);tripleTamperStatus=response.status;return response;}return fetch(url,init)};const tamperedTriple=new AuthFetch(alice,undefined,undefined,undefined,{responseTimeoutMs:1500},mutateTriple);
 await assert.rejects(tamperedTriple.fetch(`${host}//listMessages`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({messageBox:'inbox'}),requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false}));assert.equal(tripleTamperStatus,401);
 const orderedSend=await auth.fetch(`${host}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({message:{body:'ordered body',messageId:'ordered-id',messageBox:'inbox',recipient:bobId}}),requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false});assert.equal(orderedSend.status,200);assert.equal((await receiver.listMessagesLite({messageBox:'inbox'}))[0].messageId,'ordered-id');
 const bobAuth=new AuthFetch(bob,undefined,undefined,undefined,{responseTimeoutMs:3000});async function listBody(value){const response=await bobAuth.fetch(`${host}/listMessages`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(value),requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false});return {status:response.status,body:await response.json()};}
 const extended=await listBody({messageBox:'inbox',clientTag:'demo'});assert.equal(extended.status,200);assert.equal(extended.body.status,'success');
 const extendedNull=await listBody({messageBox:'inbox',clientTag:null});assert.equal(extendedNull.status,200);const extendedBool=await listBody({messageBox:'inbox',clientTag:true});assert.equal(extendedBool.status,200);
 let boolTamperStatus;const mutateBool=async(url,init)=>{const headers=new Headers(init.headers);if(String(url).endsWith('/listMessages')&&headers.has('x-bsv-auth-request-id')){const response=await fetch(url,{...init,body:String(init.body).replace('"clientTag":true','"clientTag":false')});boolTamperStatus=response.status;return response;}return fetch(url,init)};const tamperedBool=new AuthFetch(bob,undefined,undefined,undefined,{responseTimeoutMs:1500},mutateBool);
 await assert.rejects(tamperedBool.fetch(`${host}/listMessages`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({messageBox:'inbox',clientTag:true}),requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false}));assert.equal(boolTamperStatus,401);
 let tagTamperStatus;const mutateTag=async(url,init)=>{const headers=new Headers(init.headers);if(String(url).endsWith('/listMessages')&&headers.has('x-bsv-auth-request-id')){const response=await fetch(url,{...init,body:String(init.body).replace('"clientTag":"demo"','"clientTag":"fake"')});tagTamperStatus=response.status;return response;}return fetch(url,init)};const tamperedTag=new AuthFetch(bob,undefined,undefined,undefined,{responseTimeoutMs:1500},mutateTag);
 await assert.rejects(tamperedTag.fetch(`${host}/listMessages`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({messageBox:'inbox',clientTag:'demo'}),requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false}));assert.equal(tagTamperStatus,401);
 const skipped=await listBody({messageBox:'inbox',limit:2,skip:2});assert.equal(skipped.status,200);assert.equal(skipped.body.offset,2);assert.deepEqual(skipped.body.messages,[]);
 const defaults=await listBody({messageBox:'inbox',limit:null,offset:null});assert.equal(defaults.status,200);assert.equal(defaults.body.offset,0);assert.equal(defaults.body.messages.length,1);
 const mismatch=await listBody({messageBox:'inbox',offset:1,skip:2});assert.equal(mismatch.status,400);assert.equal(mismatch.body.code,'ERR_INVALID_OFFSET');
 const invalidLimit=await listBody({messageBox:'inbox',limit:0});assert.equal(invalidLimit.status,400);assert.equal(invalidLimit.body.code,'ERR_INVALID_LIMIT');
 let skipTamperStatus;const mutateSkip=async(url,init)=>{const headers=new Headers(init.headers);if(String(url).endsWith('/listMessages')&&headers.has('x-bsv-auth-request-id')){const response=await fetch(url,{...init,body:String(init.body).replace('\"skip\":2','\"skip\":1')});skipTamperStatus=response.status;return response;}return fetch(url,init)};const tamperedSkip=new AuthFetch(bob,undefined,undefined,undefined,{responseTimeoutMs:1500},mutateSkip);
 await assert.rejects(tamperedSkip.fetch(`${host}/listMessages`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({messageBox:'inbox',limit:2,skip:2}),requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false}));assert.equal(skipTamperStatus,401);

 assert.equal(await receiver.acknowledgeMessage({messageIds:['ordered-id'],host}),'success');
 const orderedDevice=await auth.fetch(`${host}/registerDevice`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({platform:'web',fcmToken:'fake-ordered-token'}),requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false});assert.equal(orderedDevice.status,200);
 const orderedPermission=await auth.fetch(`${host}/permissions/set`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({recipientFee:0,messageBox:'inbox'}),requireMutualAuth:true,expectedIdentityKey:expected,allowPayments:false});assert.equal(orderedPermission.status,200);
 await assert.rejects(sender.sendMessage({recipient:bobId,messageBox:'not-configured',messageId:'denied',body:'no write',skipEncryption:true,checkPermissions:false},host),/HTTP 503/);
 await receiver.setMessageBoxPermission({messageBox:'inbox',recipientFee:-1,sender:aliceId},host);
 await assert.rejects(sender.sendMessage({recipient:bobId,messageBox:'inbox',messageId:'blocked',body:'blocked',skipEncryption:true,checkPermissions:false},host),/HTTP 403/);
 assert.deepEqual(await receiver.listMessagesLite({messageBox:'inbox'}),[]);
 await receiver.setMessageBoxPermission({messageBox:'inbox',recipientFee:0,sender:aliceId},host);
 await receiver.registerDevice({fcmToken:'fake-runtime-device',deviceId:'test-device',platform:'ios'},host);
 const sent=await sender.sendMessage({recipient:bobId,messageBox:'inbox',messageId:'restart-message',body:'runtime hello',skipEncryption:true,checkPermissions:false},host);assert.equal(sent.messageId,'restart-message');
 assert.deepEqual(await sender.listMessagesLite({messageBox:'inbox'}),[]);
 await writeFile(configFile,JSON.stringify({bind:ready.address,dataDir:dir,identityKeyFile:keyFile,freeBoxes:['inbox']}));
 const beforeRestart=handshakes,originalAddress=ready.address;assert.ok(beforeRestart>0,'handshake counter must observe the initial SDK handshake');
 await stop();ready=await start();assert.equal(ready.identityKey,expected);assert.equal(ready.address,originalAddress);host=`http://${ready.address}`;
 const messages=await receiver.listMessagesLite({messageBox:'inbox'});assert.equal(messages.length,1);assert.equal(messages[0].messageId,'restart-message');assert.equal(messages[0].body,'runtime hello');assert.equal(handshakes,beforeRestart,'existing SDK session should survive restart without a new handshake');
 assert.equal((await receiver.listRegisteredDevices(host)).some(d=>d.deviceId==='test-device'),true);
 assert.equal(await receiver.acknowledgeMessage({messageIds:['restart-message'],host}),'success');
 assert.deepEqual(await receiver.listMessagesLite({messageBox:'inbox'}),[]);
 await stop();console.log('Fixed SDK and MessageBoxClient: loopback runtime mutual auth, free send/list/ack, policy, device and restart persistence passed; payments and WebSocket disabled.');
}finally{
 globalThis.fetch=nativeFetch;
 if(child&&child.exitCode===null&&child.signalCode===null){const exited=once(child,'exit');child.kill('SIGKILL');await exited.catch(()=>{});}
 await rm(dir,{recursive:true,force:true});
}
