// Official pinned Socket.IO client against an unauthenticated, test-only
// loopback protocol fixture. This is NOT AuthSocket or MessageBox WS coverage.
const {readFileSync}=require('node:fs');
const {createHash}=require('node:crypto');
const {spawn}=require('node:child_process');
const {createInterface}=require('node:readline');
const {once}=require('node:events');
const assert=require('node:assert/strict');
(async()=>{
 const bytes=readFileSync(process.env.SOCKETIO_UMD);
 assert.equal(createHash('sha256').update(bytes).digest('hex'),'bc425714aa8f2547d6939e3721ebafd3830a7562a1f6cb08acc1e794bd707954');
 const io=require(process.env.SOCKETIO_UMD);
 const child=spawn(process.env.SOCKETIO_TEST_FIXTURE,[],{stdio:['ignore','pipe','inherit']});
 const exited=once(child,'exit');
 try {
  const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();const line=await Promise.race([lines.next(),exited.then(([code,signal])=>({early:{code,signal}}))]);assert.ok(!line.early,`fixture exited: ${JSON.stringify(line.early)}`);const port=Number(line.value);assert.ok(port>0);
  const socket=io(`http://127.0.0.1:${port}`,{transports:['websocket'],forceNew:true,reconnection:false,timeout:5000});
  const result=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('probe timeout')),5000);socket.on('connect_error',reject);socket.on('connect',()=>socket.emit('probe',{text:'hello',count:2}));socket.on('reply',data=>{clearTimeout(timer);resolve(data);});});
  assert.deepEqual(result,{echo:'hello',count:2});socket.disconnect();
  const [code]=await exited;assert.equal(code,0);
  console.log('Fixed Socket.IO 4.8.3 UMD: explicit WebSocket transport, Engine.IO ping/pong and synthetic event exchange passed; no authentication or MessageBox routes tested.');
 } finally {if(child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await exited.catch(()=>{});}}
})().catch(error=>{console.error(error);process.exitCode=1;});
