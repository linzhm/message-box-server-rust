// Fixed Git AuthSocket client + SDK + official Socket.IO UMD, test-only echo.
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {once} from 'node:events';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const {AuthSocketClient}=await import('@bsv/authsocket-client');
const {default:ProtoWallet}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/wallet/ProtoWallet.ts`));
const {default:PrivateKey}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/primitives/PrivateKey.ts`));
const child=spawn(process.env.AUTHSOCKET_TEST_FIXTURE,[],{stdio:['ignore','pipe','inherit']});
const exited=once(child,'exit');
try {
 const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();
 const line=await Promise.race([lines.next(),exited.then(([code,signal])=>({early:{code,signal}}))]);
 assert.ok(!line.early,`fixture exited: ${JSON.stringify(line.early)}`);const port=Number(line.value);assert.ok(port>0);
 const serverKey=new PrivateKey(3).toPublicKey().toString();
 const socket=AuthSocketClient(`http://127.0.0.1:${port}`,{wallet:new ProtoWallet(new PrivateKey(2)),expectedServerIdentityKey:serverKey,managerOptions:{transports:['websocket'],forceNew:true,reconnection:false,timeout:5000},onError:(error,context)=>console.error('AuthSocket error',error,context)});
 const reply=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('AuthSocket timeout')),10000);socket.on('connect',()=>socket.emit('probe',{text:'hello'}));socket.on('reply',data=>{clearTimeout(timer);resolve(data)});});
 assert.deepEqual(reply,{echo:'hello'});socket.disconnect();
 const [code]=await exited;assert.equal(code,0);
 console.log('Fixed Git AuthSocketClient and SDK: signed synthetic event echo over official Git Socket.IO UMD WebSocket loopback passed. Not MessageBox rooms or production.');
} finally {if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await exited.catch(()=>{});}}
