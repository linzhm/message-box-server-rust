// Issue #6 default polling -> WebSocket and one reconnect. Run only in the authorized test environment.
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {once} from 'node:events';
import {pathToFileURL} from 'node:url';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import assert from 'node:assert/strict';
const {AuthSocketClient}=await import('@bsv/authsocket-client');
const {default:ProtoWallet}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/wallet/ProtoWallet.ts`));
const {default:PrivateKey}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/primitives/PrivateKey.ts`));
const dir=await mkdtemp(join(tmpdir(),'messagebox-runtime-ws-'));
let child,socket,exited;
try {
 const keyFile=join(dir,'identity.key'),configFile=join(dir,'config.json');
 await writeFile(keyFile,'0'.repeat(63)+'3\n',{mode:0o600});
 await writeFile(configFile,JSON.stringify({bind:'127.0.0.1:0',dataDir:dir,identityKeyFile:keyFile,freeBoxes:['inbox'],enableWebSockets:true}));
 child=spawn(process.env.MESSAGEBOX_SERVER,[configFile],{stdio:['ignore','pipe','inherit']});
 exited=once(child,'exit');const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();
 const ready=await Promise.race([lines.next(),exited.then(([code,signal])=>({early:{code,signal}}))]);
 assert.ok(!ready.early,`runtime exited before ready: ${JSON.stringify(ready.early)}`);
 const {address,identityKey}=JSON.parse(ready.value),key=new PrivateKey(2),self=key.toPublicKey().toString(),other=new PrivateKey(4).toPublicKey().toString();
 socket=AuthSocketClient(`http://${address}`,{wallet:new ProtoWallet(key),expectedServerIdentityKey:identityKey,managerOptions:{forceNew:true,reconnection:true,reconnectionDelay:50,reconnectionDelayMax:100,timeout:5000},onError:(error,context)=>console.error('AuthSocket error',error,context)});
 let lastGeneral,handshakes=0;const ioSocket=socket.ioSocket,emitOriginal=ioSocket.emit.bind(ioSocket);ioSocket.emit=(event,...args)=>{if(event==='authMessage'&&args[0]?.messageType==='initialRequest'){handshakes++};if(event==='authMessage'&&args[0]?.messageType==='general')lastGeneral=structuredClone(args[0]);return emitOriginal(event,...args)};
 function wait(event){return new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error(`${event} timeout`)),8000);socket.on(event,data=>{clearTimeout(timer);resolve(data)});});}
 const authenticated=wait('authenticationSuccess');socket.on('connect',()=>socket.emit('authenticated',{identityKey:self}));assert.deepEqual(await authenticated,{status:'success'});
 await new Promise((resolve,reject)=>{if(ioSocket.io.engine.transport.name==='websocket')return resolve();const timer=setTimeout(()=>reject(Error('default transport failed to upgrade')),8000);ioSocket.io.engine.once('upgrade',()=>{clearTimeout(timer);resolve()});});assert.equal(ioSocket.io.engine.transport.name,'websocket');
 const joined=wait('joinedRoom');socket.emit('joinRoom',`${self}-inbox`);assert.deepEqual(await joined,{roomId:`${self}-inbox`});
 const denied=wait('joinFailed');socket.emit('joinRoom',`${other}-inbox`);const denial=await denied;assert.equal(denial.code,'ERR_WEBSOCKET_ROOM_NOT_OWNED');
 const oddRoom=wait('joinFailed');socket.emit('joinRoom','\u0085');assert.equal((await oddRoom).code,'ERR_WEBSOCKET_ROOM_NOT_OWNED');
 const ack=wait(`sendMessageAck-${other}-inbox`);socket.emit('sendMessage',{roomId:`${other}-inbox`,message:{messageId:'test',recipient:other,body:'hello'}});assert.deepEqual(await ack,{status:'success',messageId:'test'});
 const left=wait('leftRoom');socket.emit('leaveRoom',`${self}-inbox`);assert.deepEqual(await left,{roomId:`${self}-inbox`});
 assert.ok(handshakes>0);const prev=handshakes;const reauth=wait('authenticationSuccess');ioSocket.io.engine.transport.ws.close();await reauth;assert.equal(handshakes,prev,'same Peer should reuse WS session');const rejoin=wait('joinedRoom');socket.emit('joinRoom',`${self}-inbox`);assert.deepEqual(await rejoin,{roomId:`${self}-inbox`});
 socket.disconnect();socket=undefined;assert.equal(child.kill('SIGINT'),true);const [code,signal]=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('server failed to exit after SIGINT')),8000);exited.then(result=>{clearTimeout(timer);resolve(result)},reject)});assert.equal(code,0,`runtime exit ${code}/${signal}`);child=undefined;
 console.log('Fixed Git AuthSocketClient: default polling -> WebSocket, BRC authentication, own-room policy, one same-Peer reconnect resumes WS session, and shutdown. Cross-node delivery not tested.');
} finally {socket?.disconnect();if(child&&child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await exited.catch(()=>{});}await rm(dir,{recursive:true,force:true});}
