// Fixed Git SDK high-level MessageBoxClient against disposable loopback runtime.
// Public test keys only, no payment, no real credentials or external network.
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {pathToFileURL} from 'node:url';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {once} from 'node:events';
import assert from 'node:assert/strict';
const nativeFetch=globalThis.fetch;let handshakes=0;
globalThis.fetch=(url,options)=>{if(String(url).includes('/.well-known/auth'))handshakes++;return nativeFetch(url,options);};
const sdk=process.env.SDK_SOURCE_DIR,clientSource=process.env.CLIENT_SOURCE_DIR;
const {MessageBoxClient}=await import(pathToFileURL(`${clientSource}/packages/messaging/message-box-client/src/MessageBoxClient.ts`));
const {AuthFetch}=await import(pathToFileURL(`${sdk}/src/auth/clients/AuthFetch.ts`));
const {default:ProtoWallet}=await import(pathToFileURL(`${sdk}/src/wallet/ProtoWallet.ts`));
const {default:PrivateKey}=await import(pathToFileURL(`${sdk}/src/primitives/PrivateKey.ts`));
const dir=await mkdtemp(join(tmpdir(),'messagebox-prefix-'));
const keyFile=join(dir,'key'),configFile=join(dir,'config.json');
await writeFile(keyFile,'0'.repeat(63)+'3\n',{mode:0o600});
const prefix=process.env.ROUTING_PREFIX??'/mb';
const config={bind:'127.0.0.1:0',dataDir:dir,identityKeyFile:keyFile,freeBoxes:['inbox']};
if(process.env.ROUTING_CONFIG==='1')config.routingPrefix=prefix;
if(process.env.TS_FEES==='1'){delete config.freeBoxes;config.pricingMode='ts-table';}
await writeFile(configFile,JSON.stringify(config));
let child;
async function start(){
 child=spawn(process.env.MESSAGEBOX_SERVER,[configFile],{stdio:['ignore','pipe','inherit']});
 const readyLine=createInterface({input:child.stdout})[Symbol.asyncIterator]();
 const ready=await Promise.race([readyLine.next(),once(child,'exit').then(([code])=>{throw new Error(`early exit ${code}`)}),new Promise((_,reject)=>setTimeout(()=>reject(new Error('startup timeout')),10000))]);
 return JSON.parse(ready.value);
}
async function stop(){const exited=once(child,'exit',{signal:AbortSignal.timeout(10000)});child.kill('SIGINT');assert.equal((await exited)[0],0);child=undefined;}
try {
 const ready=await start();
 const address=ready.address,server=new PrivateKey(3).toPublicKey().toString();
 const origin=`http://${address}`,host=`${origin}${prefix}`,alice=new ProtoWallet(new PrivateKey(2)),bob=new ProtoWallet(new PrivateKey(4));
 const health=await fetch(`${host}/health`);assert.equal(health.status,200);const healthBody=await health.text();const head=await fetch(`${host}/health`,{method:'HEAD'});assert.equal(head.status,200);assert.equal(await head.text(),'');assert.equal(Number(head.headers.get('content-length')),Buffer.byteLength(healthBody));assert.equal((await fetch(`${host}/ready`)).status,200);assert.notEqual((await fetch(`${origin}/health`)).status,200);
 const doubled=`${origin}//${prefix.slice(1)}`;assert.equal((await fetch(`${doubled}/health`)).status,200);
 const prefAuth=new AuthFetch(bob,undefined,undefined,undefined,{responseTimeoutMs:3000});const prefGet=await prefAuth.fetch(`${doubled}/devices?limit=1`,{method:'GET',requireMutualAuth:true,expectedIdentityKey:server,allowPayments:false});assert.equal(prefGet.status,200);
 let prefSlashStatus;const prefSlashRewrite=async(url,init)=>{const headers=new Headers(init.headers);if(String(url).includes('/devices?')&&headers.has('x-bsv-auth-request-id')){const response=await fetch(String(url).replace(`//${prefix.slice(1)}`,`///${prefix.slice(1)}`),init);prefSlashStatus=response.status;return response;}return fetch(url,init)};const prefTamper=new AuthFetch(bob,undefined,undefined,undefined,{responseTimeoutMs:1500},prefSlashRewrite);
 await assert.rejects(prefTamper.fetch(`${doubled}/devices?limit=1`,{method:'GET',requireMutualAuth:true,expectedIdentityKey:server,allowPayments:false}));assert.equal(prefSlashStatus,401);
 const bobId=new PrivateKey(4).toPublicKey().toString();
 const sender=new MessageBoxClient({host,walletClient:alice,serverIdentityKeysByHost:{[host]:server}});
 const recipient=new MessageBoxClient({host,walletClient:bob,serverIdentityKeysByHost:{[host]:server}});
 assert.deepEqual(await recipient.listMessagesLite({messageBox:'inbox'}),[]);
 const sent=await sender.sendMessage({recipient:bobId,messageBox:'inbox',messageId:'prefix-id',body:'test',skipEncryption:true,checkPermissions:false},host);assert.equal(sent.messageId,'prefix-id');
 assert.equal((await recipient.listMessagesLite({messageBox:'inbox'}))[0].messageId,'prefix-id');
 await recipient.setMessageBoxPermission({messageBox:'inbox',recipientFee:0},host);
 const checked=await sender.sendMessage({recipient:bobId,messageBox:'inbox',messageId:'checked-id',body:'checked',skipEncryption:true,checkPermissions:true},host);assert.equal(checked.messageId,'checked-id');
 await recipient.registerDevice({fcmToken:'fake-prefix-device',deviceId:'fake-device',platform:'ios'},host);assert.equal((await recipient.listRegisteredDevices(host)).some(d=>d.deviceId==='fake-device'),true);
 assert.equal(await recipient.acknowledgeMessage({messageIds:['prefix-id','checked-id'],host}),'success');
 assert.deepEqual(await recipient.listMessagesLite({messageBox:'inbox'}),[]);
 if(process.env.TS_FEES==='1'){
  const order=await sender.sendMessage({recipient:bobId,messageBox:'orders',messageId:'orders-id',body:'free unknown box',skipEncryption:true,checkPermissions:true},host);assert.equal(order.messageId,'orders-id');
  assert.equal((await recipient.listMessagesLite({messageBox:'orders'}))[0].messageId,'orders-id');
  assert.equal(await recipient.acknowledgeMessage({messageIds:['orders-id'],host}),'success');
  const pricing=new AuthFetch(alice,undefined,undefined,undefined,{responseTimeoutMs:3000});
  const quote=await pricing.fetch(`${host}/permissions/quote?recipient=${bobId}&messageBox=notifications`,{method:'GET',requireMutualAuth:true,expectedIdentityKey:server,allowPayments:false});assert.equal(quote.status,200);const result=await quote.json();assert.equal(result.quote.deliveryFee,10);assert.equal(result.quote.recipientFee,10);
 }
 await sender.sendMessage({recipient:bobId,messageBox:'inbox',messageId:'prefix-restart',body:'persisted',skipEncryption:true,checkPermissions:false},host);
 config.bind=address;await writeFile(configFile,JSON.stringify(config));const beforeRestart=handshakes;assert.ok(beforeRestart>0);
 await stop();const restarted=await start();assert.equal(restarted.address,address);assert.equal(restarted.identityKey,server);
 assert.equal((await recipient.listMessagesLite({messageBox:'inbox'}))[0].messageId,'prefix-restart');assert.equal(handshakes,beforeRestart);
 assert.equal((await recipient.listRegisteredDevices(host)).some(d=>d.deviceId==='fake-device'),true);
 assert.equal(await recipient.acknowledgeMessage({messageIds:['prefix-restart'],host}),'success');
 assert.deepEqual(await recipient.listMessagesLite({messageBox:'inbox'}),[]);assert.equal(handshakes,beforeRestart);
 let status;const rewrite=async(url,init)=>{const headers=new Headers(init.headers);if(String(url).endsWith('/listMessages')&&headers.has('x-bsv-auth-request-id')){const response=await fetch(String(url).replace('/listMessages',`${prefix}/listMessages`),init);status=response.status;return response;}return fetch(url,init)};
 const auth=new AuthFetch(bob,undefined,undefined,undefined,{responseTimeoutMs:1500},rewrite);
 await assert.rejects(auth.fetch(`${origin}/listMessages`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({messageBox:'inbox'}),requireMutualAuth:true,expectedIdentityKey:server,allowPayments:false}));assert.equal(status,401);
 await stop();
 console.log('Fixed SDK MessageBoxClient prefix send/list/ack, restart persistence and path-signature mutation passed on loopback; no payment.');
} finally {globalThis.fetch=nativeFetch;if(child&&child.exitCode===null&&child.signalCode===null){const exited=once(child,'exit');child.kill('SIGKILL');await exited.catch(()=>{});}await rm(dir,{recursive:true,force:true});}
