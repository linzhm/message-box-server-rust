// Fixed Git MessageBoxClient sends and receives a live WS message with public test keys.
import {spawn} from 'node:child_process';import {createInterface} from 'node:readline';import {pathToFileURL} from 'node:url';import {mkdtemp,rm,writeFile} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import {once} from 'node:events';import assert from 'node:assert/strict';
const nativeFetch=globalThis.fetch;let httpSends=0;globalThis.fetch=(url,options)=>{if(String(url).endsWith('/sendMessage'))httpSends++;return nativeFetch(url,options)};
const sdk=process.env.SDK_SOURCE_DIR,clients=process.env.CLIENT_SOURCE_DIR;
const {MessageBoxClient}=await import(pathToFileURL(`${clients}/packages/messaging/message-box-client/src/MessageBoxClient.ts`));
const {default:ProtoWallet}=await import(pathToFileURL(`${sdk}/src/wallet/ProtoWallet.ts`));const {default:PrivateKey}=await import(pathToFileURL(`${sdk}/src/primitives/PrivateKey.ts`));
const dir=await mkdtemp(join(tmpdir(),'messagebox-ws-fallback-'));let child,sender,receiver,exited;
try {
 const key=join(dir,'key'),config=join(dir,'config.json');await writeFile(key,'0'.repeat(63)+'3\n',{mode:0o600});await writeFile(config,JSON.stringify({bind:'127.0.0.1:0',dataDir:dir,identityKeyFile:key,freeBoxes:['inbox'],enableWebSockets:true}));
 child=spawn(process.env.MESSAGEBOX_SERVER,[config],{stdio:['ignore','pipe','inherit']});exited=once(child,'exit');const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();const first=await Promise.race([lines.next(),exited.then(([code,signal])=>({early:{code,signal}}))]);assert.ok(!first.early&&!first.done,'runtime did not become ready');const ready=JSON.parse(first.value),host=`http://${ready.address}`,server=ready.identityKey,bob=new PrivateKey(4).toPublicKey().toString();
 function wallet(n){const w=new ProtoWallet(new PrivateKey(n));w.createAction=async()=>{throw Error('Payments disabled');};return w;}
 const options={host,serverIdentityKeysByHost:{[host]:server},socketOptions:{managerOptions:{transports:['websocket'],forceNew:true,reconnection:false}}};
 sender=new MessageBoxClient({...structuredClone(options),walletClient:wallet(2)});receiver=new MessageBoxClient({...structuredClone(options),walletClient:wallet(4)});
 let liveResolve;const live=new Promise(resolve=>{liveResolve=resolve});await receiver.listenForLiveMessages({messageBox:'inbox',onMessage:liveResolve});
 const room=`${bob}-inbox`;const joined=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('join timeout')),8000);receiver.socket.on('joinedRoom',data=>{if(data.roomId===room){clearTimeout(timer);resolve(data)}})});receiver.socket.emit('joinRoom',room);await joined;
 await sender.joinRoom('inbox');assert.equal(sender.socket.connected,true);
 const ack=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('WS ack timeout')),8000);sender.socket.on(`sendMessageAck-${bob}-inbox`,data=>{clearTimeout(timer);resolve(data)});});
 const sent=sender.sendLiveMessage({recipient:bob,messageBox:'inbox',messageId:'ws-live-client',body:'hello',skipEncryption:true,checkPermissions:false},host);
 assert.deepEqual(await ack,{status:'success',messageId:'ws-live-client'});const response=await sent;assert.equal(response.messageId,'ws-live-client');
 const observed=await Promise.race([live,new Promise((_,reject)=>setTimeout(()=>reject(Error('live push timeout')),8000))]);assert.equal(observed.messageId,'ws-live-client');assert.equal(observed.body,'hello');assert.equal(httpSends,0);
 const messages=await receiver.listMessagesLite({messageBox:'inbox'});assert.equal(messages.length,1);assert.equal(messages[0].messageId,'ws-live-client');assert.equal(messages[0].body,'hello');
 await sender.disconnectWebSocket();await receiver.disconnectWebSocket();sender=undefined;receiver=undefined;child.kill('SIGINT');const [code,signal]=await exited;assert.equal(code,0,`${code}/${signal}`);child=undefined;
 console.log('Fixed MessageBoxClient sent and received one WS live message, persisted for HTTP listing; no HTTP send fallback or payment.');
} finally {await sender?.disconnectWebSocket();await receiver?.disconnectWebSocket();if(child&&child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await exited.catch(()=>{});}await rm(dir,{recursive:true,force:true});}
