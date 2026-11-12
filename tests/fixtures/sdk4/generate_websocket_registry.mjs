// Execute the fixed TS registry against synthetic sockets, without a network.
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const path=`${process.env.REGISTRY_SOURCE_DIR}/infra/message-box-server/src/security/webSocketConnections.ts`;
const bytes=await readFile(path);assert.equal(createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex'),'bc37053bf8bdab315e59feabdead368f99c155dd');
const source=bytes.toString().replace(/^import .*$/gm,'').replace(/\bexport\s+/g,'');
const ts=(await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
const js=ts.transpileModule(`${source}\nreturn {WebSocketConnectionRegistry,WebSocketMinuteRateLimiter}`,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const {WebSocketConnectionRegistry:Registry,WebSocketMinuteRateLimiter:Rate}=new Function(js)(), registry=new Registry(), sockets=new Map();
const operations=[
 ['register','a',2],['register','b',2],['register','c',2],['join','a','room',2],['authenticate','a','alice',1],['authenticate','a','alice',1],['authenticate','a','bob',1],['authenticate','b','alice',1],['authenticate','b','bob',1],['join','a','room',1],['join','a','room',1],['join','a','room2',1],['join','b','room',1],['select','alice','room',1],['select','bob','room',1],['disconnect','a'],['register','c',2],['authenticate','c','alice',3],['join','c','room',2],['register','d',-1],['authenticate','d','alice',3],['join','d','room',2],['register','e',-1],['authenticate','e','alice',3],['join','e','room',2],['select','alice','room',2],['select','alice','room',-1],['select','alice','room',0],['leave','d','room'],['select','alice','room',2],['state','d'],['state','a'],['sockets'],['clear'],['sockets']
];
const results=[];
for(const [op,...args] of operations){let result=null;
 if(op==='register'){const [id,max]=args;const socket={id,ioSocket:{once(name,cb){assert.equal(name,'disconnect');socket.disconnect=cb;}}};result=registry.register(socket,undefined,max);if(result)sockets.set(id,socket);}
 else if(op==='authenticate')result=registry.authenticate(...args);
 else if(op==='join')result=registry.join(...args);
 else if(op==='leave')registry.leave(...args);
 else if(op==='disconnect')sockets.get(args[0]).disconnect('test');
 else if(op==='select')result=registry.recipientSockets(...args).map(socket=>socket.id);
 else if(op==='state')result={authenticated:registry.isAuthenticated(args[0]),identity:registry.identityKey(args[0])??null,rooms:registry.roomCount(args[0]),connections:registry.connectionCount()};
 else if(op==='sockets')result=[...registry.sockets()].map(socket=>socket.id);
 else if(op==='clear')registry.clear();else throw Error(op);
 results.push({operation:[op,...args],result});
}
const rates=[{limit:2,start:100,times:[100,101,59999,60099,60100,60101,120100]},{limit:-1,start:0,times:[0,1,2,60000]},{limit:0,start:0,times:[0,60000]}].map(c=>{const rate=new Rate(c.limit,c.start);return {...c,results:c.times.map(t=>rate.consume(t))}});
await writeFile(process.argv[2],JSON.stringify({rates,sourceBlob:'bc37053bf8bdab315e59feabdead368f99c155dd',results},null,2)+'\n');console.log(`Generated ${results.length} registry operations from fixed TS source.`);
