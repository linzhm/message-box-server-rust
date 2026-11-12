import {pathToFileURL} from 'node:url';
const sdk=process.env.SDK_SOURCE_DIR, middleware=process.env.AUTH_MIDDLEWARE_SOURCE_DIR;
const {Writer,toArray}=await import(pathToFileURL(`${sdk}/src/primitives/utils.ts`));
const {stringifyBRC100}=await import(pathToFileURL(`${sdk}/src/wallet/BRC100ByteEncoding.ts`));
const {writeUrlToWriter,writeRequestHeadersToWriter,writeBodyToWriter,writeHeaderPair}=await import(pathToFileURL(`${middleware}/authMiddlewareHelpers.ts`));
const requestId=Array.from({length:32},(_,i)=>i);
const cases=[];
for (const [method,url,headers,body,canonicalHeaders,canonicalBody] of [
 ['GET','http://localhost/devices?limit=2',{'x-bsv-auth-version':'0.1','x-bsv-foo':'bar'}, {},[['x-bsv-foo','bar']],null],
 ['POST','http://localhost/sendMessage',{'content-type':'application/json; charset=utf-8','content-length':'16','x-bsv-zed':'v2','x-bsv-alpha':'v1','x-bsv-auth-nonce':'ignored'}, {z:2,a:'猫'},[['content-type','application/json'],['x-bsv-alpha','v1'],['x-bsv-zed','v2']],stringifyBRC100({z:2,a:'猫'})],
 ['POST','http://localhost/binary',{'content-type':'application/octet-stream','content-length':'0'}, [],[['content-type','application/octet-stream']],''],
 ['POST','http://localhost/text',{'content-type':'text/plain','content-length':'0'}, '',[['content-type','text/plain']],null],
 ['POST','http://localhost/sendMessage',{'content-type':'application/json','x-bsv-payment':JSON.stringify({derivationPrefix:'AA==',derivationSuffix:'AQ==',transaction:'Ag=='})}, {messageBox:'inbox'},[['content-type','application/json'],['x-bsv-payment',JSON.stringify({derivationPrefix:'AA==',derivationSuffix:'AQ==',transaction:'Ag=='})]],stringifyBRC100({messageBox:'inbox'})],
]) {
 const writer=new Writer(); writer.write(requestId); writer.writeVarIntNum(method.length); writer.write(toArray(method));
 const parsed=new URL(url);writeUrlToWriter(parsed,writer);writeRequestHeadersToWriter({headers},writer);writeBodyToWriter({headers,body},writer);
 cases.push({requestId,method,path:parsed.pathname||null,query:parsed.search||null,headers:canonicalHeaders,body:canonicalBody,frameHex:Buffer.from(writer.toArray()).toString('hex')});
}
// The response builder is module-private. Reproduce its source-described sequence
// using the actual SDK Writer and middleware header-pair helper.
const responseCases=[];
for (const [status,headers,body] of [[200,[["x-bsv-extra","ok"]],'{"status":"success"}'],[204,[],null]]) {
 const w=new Writer();w.write(requestId);w.writeVarIntNum(status);w.writeVarIntNum(headers.length);
 for(const [key,value] of headers)writeHeaderPair(w,key,value);
 const b=body===null?[]:toArray(body,'utf8');if(b.length){w.writeVarIntNum(b.length);w.write(b);}else w.writeVarIntNum(-1);
 responseCases.push({requestId,status,headers,body,frameHex:Buffer.from(w.toArray()).toString('hex')});
}
const compactSizes=[];
for(const n of [-1,0,252,253,65535,65536,4294967296]){const writer=new Writer();writer.writeVarIntNum(n);compactSizes.push({value:n,hex:Buffer.from(writer.toArray()).toString('hex')});}
console.log(JSON.stringify({source:'ts-stack 52d36a5 auth middleware helpers and SDK Writer TypeScript source',cases,responseCases,compactSizes},null,2));
