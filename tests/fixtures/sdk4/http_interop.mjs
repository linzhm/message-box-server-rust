// Actual loopback HTTP with fixed SDK Git-source AuthFetch/ProtoWallet.
// Test keys, disposable SQLite and only the narrow supported GET route.
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {pathToFileURL} from 'node:url';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import assert from 'node:assert/strict';
const root=process.env.SDK_SOURCE_DIR;
const {AuthFetch}=await import(pathToFileURL(`${root}/src/auth/clients/AuthFetch.ts`));
const {default:ProtoWallet}=await import(pathToFileURL(`${root}/src/wallet/ProtoWallet.ts`));
const {default:PrivateKey}=await import(pathToFileURL(`${root}/src/primitives/PrivateKey.ts`));
const dir=await mkdtemp(join(tmpdir(),'messagebox-http-fixture-'));
const child=spawn(process.env.AUTH_HTTP_FIXTURE,[],{stdio:['ignore','pipe','inherit'],env:{...process.env,AUTH_TEST_DB:join(dir,'auth.sqlite')}});
const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();
try {
 const port=Number((await lines.next()).value);assert.ok(port>0);
 const url=`http://127.0.0.1:${port}/devices`,server=new PrivateKey(3).toPublicKey().toString(),client=new PrivateKey(2);
 const config={method:'GET',requireMutualAuth:true,expectedIdentityKey:server,allowPayments:false};
 let captured;
 const capture=async (url,init)=>{const h=new Headers(init.headers);if(h.has('x-bsv-auth-request-id'))captured={url,headers:h};return fetch(url,init);};
 const auth=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:3000},capture);
 const response=await auth.fetch(url,config);assert.equal(response.status,200);assert.equal(response.headers.get('x-bsv-auth-identity-key'),server);
 const result=await response.json();assert.equal(result.status,'success');assert.equal(result.devices.length,1);assert.equal(result.devices[0].fcmToken,'...cret-token');
 const postUrl=`http://127.0.0.1:${port}/listMessages`;
 const postConfig={method:'POST',headers:{'content-type':'application/json'},body:'{"messageBox":"inbox","offset":0}',requireMutualAuth:true,expectedIdentityKey:server,allowPayments:false};
 const postAuth=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:3000});
 const listed=await postAuth.fetch(postUrl,postConfig);assert.equal(listed.status,200);const inbox=await listed.json();
 assert.equal(inbox.messages.length,1);assert.equal(inbox.messages[0].messageId,'sdk-message-1');assert.equal(inbox.messages[0].sender,new PrivateKey(4).toPublicKey().toString());assert.equal(inbox.messages[0].body,'{"message":"hello from test"}');
 const secondPage=await postAuth.fetch(postUrl,{...postConfig,body:'{"messageBox":"inbox","offset":1}'});assert.equal(secondPage.status,200);assert.deepEqual((await secondPage.json()).messages,[]);
 for(const [originalBody,tamperedBody] of [
  [postConfig.body,'{"offset":0,"messageBox":"inbox"}'],
  [postConfig.body,'{"messageBox":"other","offset":0}'],
  [postConfig.body,'{"messageBox":"inbox","offset":1}'],
  ['{"messageBox":"inbox","offset":0,"limit":1}','{"messageBox":"inbox","offset":0,"limit":2}'],
  ['{"messageBox":"inbox","offset":0,"messageId":"sdk-message-1"}','{"messageBox":"inbox","offset":0,"messageId":"different-id"}'],
 ]) {
  let postObserved;
  const mutatePost=async (target,init)=>{const headers=new Headers(init.headers);if(!headers.has('x-bsv-auth-request-id'))return fetch(target,init);
   const response=await fetch(target,{...init,body:tamperedBody});postObserved={status:response.status,body:await response.clone().json()};return response;};
  const tamperedPost=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:1500},mutatePost);
  await assert.rejects(tamperedPost.fetch(postUrl,{...postConfig,body:originalBody}));assert.equal(postObserved.status,401);assert.equal(postObserved.body.code,'ERR_AUTH_FAILED');
 }
 // Mutate signed canonical send and ack bodies with fresh sessions. Neither
 // altered operation may be dispatched under the original signature.
 const devicePageUrl=`http://127.0.0.1:${port}/devices?limit=1&offset=0`;
 let devicePageObserved;
 const mutateDevicePage=async(target,init)=>{const headers=new Headers(init.headers);if(!headers.has('x-bsv-auth-request-id'))return fetch(target,init);
  const response=await fetch(target.replace('offset=0','offset=1'),init);devicePageObserved={status:response.status,body:await response.clone().json()};return response;};
 const pageAuth=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:1500},mutateDevicePage);
 await assert.rejects(pageAuth.fetch(devicePageUrl,config));assert.equal(devicePageObserved.status,401);assert.equal(devicePageObserved.body.code,'ERR_AUTH_FAILED');
 const quoteUrl=`http://127.0.0.1:${port}/permissions/quote?recipient=${client.toPublicKey().toString()}&messageBox=paidbox`;
 let quoteObserved;
 const tamperQuery=async (target,init)=>{const headers=new Headers(init.headers);if(!headers.has('x-bsv-auth-request-id'))return fetch(target,init);
  const response=await fetch(target.replace('messageBox=paidbox','messageBox=inbox'),init);quoteObserved={status:response.status,body:await response.clone().json()};return response;};
 const quoteAuth=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:1500},tamperQuery);
 await assert.rejects(quoteAuth.fetch(quoteUrl,config));assert.equal(quoteObserved.status,401);assert.equal(quoteObserved.body.code,'ERR_AUTH_FAILED');
 const first=client.toPublicKey().toString(),second=new PrivateKey(4).toPublicKey().toString(),third=new PrivateKey(3).toPublicKey().toString();
 const multiUrl=`http://127.0.0.1:${port}/permissions/quote?recipient=${first}&recipient=${second}&messageBox=inbox`;
 let multiObserved;
 const tamperMulti=async (target,init)=>{const headers=new Headers(init.headers);if(!headers.has('x-bsv-auth-request-id'))return fetch(target,init);
  const response=await fetch(target.replace(`recipient=${second}`,`recipient=${third}`),init);multiObserved={status:response.status,body:await response.clone().json()};return response;};
 const multiAuth=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:1500},tamperMulti);
 await assert.rejects(multiAuth.fetch(multiUrl,config));assert.equal(multiObserved.status,401);assert.equal(multiObserved.body.code,'ERR_AUTH_FAILED');
 const duplicateUrl=`http://127.0.0.1:${port}/permissions/quote?recipient=${first}&recipient=${first}&messageBox=inbox`;
 const duplicate=await postAuth.fetch(duplicateUrl,config);assert.equal(duplicate.status,400);assert.equal((await duplicate.json()).code,'ERR_DUPLICATE_RECIPIENT');
 const maxParams=new URLSearchParams();
 for(let i=10;i<110;i++)maxParams.append('recipient',new PrivateKey(i).toPublicKey().toString());
 maxParams.append('messageBox','inbox');
 const maxQuote=await postAuth.fetch(`http://127.0.0.1:${port}/permissions/quote?${maxParams}`,config);
 assert.equal(maxQuote.status,200);const maxPayload=await maxQuote.json();
 assert.equal(maxPayload.quotesByRecipient.length,100);assert.equal(maxPayload.totals.totalForPayableRecipients,0);
 const recipient=client.toPublicKey().toString();
 const sendBody=JSON.stringify({message:{recipient,messageBox:'inbox',messageId:'tamper-id',body:'before'}});
 const alteredSend=JSON.stringify({message:{recipient,messageBox:'inbox',messageId:'tamper-id',body:'after'}});
 for(const [path,original,altered] of [
  ['/sendMessage',sendBody,alteredSend],
  ['/acknowledgeMessage',JSON.stringify({messageIds:['different-id']}),JSON.stringify({messageIds:['sdk-message-1']})],
 ]) {
  let observed;
  const mutate=async (target,init)=>{const headers=new Headers(init.headers);if(!headers.has('x-bsv-auth-request-id'))return fetch(target,init);
   const response=await fetch(target,{...init,body:altered});observed={status:response.status,body:await response.clone().json()};return response;};
  const fresh=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:1500},mutate);
  await assert.rejects(fresh.fetch(`http://127.0.0.1:${port}${path}`,{...postConfig,body:original}));
  assert.equal(observed.status,401);assert.equal(observed.body.code,'ERR_AUTH_FAILED');
 }
 const listPermissionUrl=`http://127.0.0.1:${port}/permissions/list?messageBox=inbox&limit=1&offset=0`;
 let listPermissionObserved;
 const mutateListPermission=async(target,init)=>{const headers=new Headers(init.headers);if(!headers.has('x-bsv-auth-request-id'))return fetch(target,init);
  const response=await fetch(target.replace('offset=0','offset=1'),init);listPermissionObserved={status:response.status,body:await response.clone().json()};return response;};
 const listPermissionAuth=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:1500},mutateListPermission);
 await assert.rejects(listPermissionAuth.fetch(listPermissionUrl,config));assert.equal(listPermissionObserved.status,401);assert.equal(listPermissionObserved.body.code,'ERR_AUTH_FAILED');
 const permissionUrl=`http://127.0.0.1:${port}/permissions/get?messageBox=tamper-permission`;
 const permissionBody=JSON.stringify({messageBox:'tamper-permission',recipientFee:0});
 const alteredPermission=JSON.stringify({messageBox:'tamper-permission',recipientFee:-1});
 let permissionObserved;
 const mutatePermission=async(target,init)=>{const headers=new Headers(init.headers);if(!headers.has('x-bsv-auth-request-id'))return fetch(target,init);
  const response=await fetch(target,{...init,body:alteredPermission});permissionObserved={status:response.status,body:await response.clone().json()};return response;};
 const permissionAuth=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:1500},mutatePermission);
 await assert.rejects(permissionAuth.fetch(`http://127.0.0.1:${port}/permissions/set`,{...postConfig,body:permissionBody}));
 assert.equal(permissionObserved.status,401);assert.equal(permissionObserved.body.code,'ERR_AUTH_FAILED');
 const unchangedPermission=await postAuth.fetch(permissionUrl,config);assert.equal((await unchangedPermission.json()).permission,null);
 let permissionQueryObserved;
 const mutatePermissionQuery=async(target,init)=>{const headers=new Headers(init.headers);if(!headers.has('x-bsv-auth-request-id'))return fetch(target,init);
  const response=await fetch(target.replace('tamper-permission','other-permission'),init);permissionQueryObserved={status:response.status,body:await response.clone().json()};return response;};
 const queryAuth=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:1500},mutatePermissionQuery);
 await assert.rejects(queryAuth.fetch(permissionUrl,config));assert.equal(permissionQueryObserved.status,401);assert.equal(permissionQueryObserved.body.code,'ERR_AUTH_FAILED');
 const deviceBody=JSON.stringify({fcmToken:'fake-tamper-token',deviceId:'original',platform:'ios'});
 const deviceAltered=JSON.stringify({fcmToken:'fake-tamper-token',deviceId:'modified',platform:'ios'});
 let deviceObserved;
 const mutateDevice=async(target,init)=>{const headers=new Headers(init.headers);if(!headers.has('x-bsv-auth-request-id'))return fetch(target,init);
  const response=await fetch(target,{...init,body:deviceAltered});deviceObserved={status:response.status,body:await response.clone().json()};return response;};
 const deviceAuth=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:1500},mutateDevice);
 await assert.rejects(deviceAuth.fetch(`http://127.0.0.1:${port}/registerDevice`,{...postConfig,body:deviceBody}));
 assert.equal(deviceObserved.status,401);assert.equal(deviceObserved.body.code,'ERR_AUTH_FAILED');
 const devicesAfter=await postAuth.fetch(url,config);assert.equal((await devicesAfter.json()).devices.length,1);
 const batchBody=JSON.stringify({message:{recipients:[first,second],messageBox:'inbox',messageId:['batch-tamper-1','batch-tamper-2'],body:'batch'}});
 const alteredBatch=JSON.stringify({message:{recipients:[first,third],messageBox:'inbox',messageId:['batch-tamper-1','batch-tamper-2'],body:'batch'}});
 let batchObserved;
 const mutateBatch=async(target,init)=>{const headers=new Headers(init.headers);if(!headers.has('x-bsv-auth-request-id'))return fetch(target,init);
  const response=await fetch(target,{...init,body:alteredBatch});batchObserved={status:response.status,body:await response.clone().json()};return response;};
 const batchAuth=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:1500},mutateBatch);
 await assert.rejects(batchAuth.fetch(`http://127.0.0.1:${port}/sendMessage`,{...postConfig,body:batchBody}));
 assert.equal(batchObserved.status,401);assert.equal(batchObserved.body.code,'ERR_AUTH_FAILED');
 const mismatchedBody=JSON.stringify({message:{recipients:[first,second],messageBox:'inbox',messageId:['batch-single'],body:'batch'}});
 const mismatched=await postAuth.fetch(`http://127.0.0.1:${port}/sendMessage`,{...postConfig,body:mismatchedBody});
 assert.equal(mismatched.status,400);assert.equal((await mismatched.json()).code,'ERR_MESSAGEID_COUNT_MISMATCH');
 const conflictBody=JSON.stringify({message:{recipients:[first,second],messageBox:'inbox',messageId:['batch-fresh','sdk-message-1'],body:'batch'}});
 const conflict=await postAuth.fetch(`http://127.0.0.1:${port}/sendMessage`,{...postConfig,body:conflictBody});
 assert.equal(conflict.status,400);assert.equal((await conflict.json()).code,'ERR_DUPLICATE_MESSAGE');
 const afterConflict=await postAuth.fetch(postUrl,postConfig);const conflictRows=(await afterConflict.json()).messages;
 assert.equal(conflictRows.some(message=>message.messageId==='batch-fresh'),false);
 assert.equal(conflictRows.some(message=>message.messageId==='batch-single'),false);
 assert.equal(conflictRows.some(message=>message.messageId==='batch-tamper-1'),false);
 const paidBatchBody=JSON.stringify({message:{recipients:[first,second],messageBox:'paidbox',messageId:['paid-batch-1','paid-batch-2'],body:'batch'}});
 const paidBatch=await postAuth.fetch(`http://127.0.0.1:${port}/sendMessage`,{...postConfig,body:paidBatchBody});
 assert.equal(paidBatch.status,501);assert.equal((await paidBatch.json()).code,'ERR_PAYMENT_NOT_IMPLEMENTED');
 const paidBody=JSON.stringify({message:{recipient,messageBox:'paidbox',messageId:'paid-id',body:'not delivered'}});
 const paid=await postAuth.fetch(`http://127.0.0.1:${port}/sendMessage`,{...postConfig,body:paidBody});
 assert.equal(paid.status,501);assert.equal((await paid.json()).code,'ERR_PAYMENT_NOT_IMPLEMENTED');
 const paidList=await postAuth.fetch(postUrl,{...postConfig,body:'{"messageBox":"paidbox","offset":0}'});
 assert.deepEqual((await paidList.json()).messages,[]);
 const otherAuth=new AuthFetch(new ProtoWallet(new PrivateKey(4)),undefined,undefined,undefined,{responseTimeoutMs:3000});
 const otherPaidList=await otherAuth.fetch(postUrl,{...postConfig,body:'{"messageBox":"paidbox","offset":0}'});
 assert.deepEqual((await otherPaidList.json()).messages,[]);
 const afterTampering=await postAuth.fetch(postUrl,postConfig);const retained=(await afterTampering.json()).messages;
 assert.equal(retained.some(message=>message.messageId==='tamper-id'),false);
 assert.equal(retained.some(message=>message.messageId==='sdk-message-1'),true);
 assert.ok(captured);const replay=await fetch(captured.url,{method:'GET',headers:captured.headers});assert.equal(replay.status,401);
 for(const mode of ['signature','request-id','your-nonce','identity','path']) {
  let observed;
  const mutate=async (target,init)=>{
   const headers=new Headers(init.headers);if(!headers.has('x-bsv-auth-request-id'))return fetch(target,init);
   if(mode==='signature'){const sig=headers.get('x-bsv-auth-signature');headers.set('x-bsv-auth-signature',sig.slice(0,-2)+(sig.endsWith('00')?'01':'00'));}
   if(mode==='request-id')headers.set('x-bsv-auth-request-id',Buffer.alloc(32,9).toString('base64'));
   if(mode==='your-nonce')headers.set('x-bsv-auth-your-nonce',Buffer.alloc(48,9).toString('base64'));
   if(mode==='identity')headers.set('x-bsv-auth-identity-key',new PrivateKey(4).toPublicKey().toString());
   if(mode==='path')target=`${target}?limit=1`;
   const response=await fetch(target,{...init,headers});observed={status:response.status,body:await response.clone().json()};return response;
  };
  const fresh=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:1500},mutate);
  await assert.rejects(fresh.fetch(url,config),undefined,`fresh tampered ${mode} must fail`);
  assert.ok(observed,`fresh tampered ${mode} reached server`);
  assert.equal(observed.status,401,mode);
  assert.equal(observed.body.code,'ERR_AUTH_FAILED',mode);
 }
 const plain=await fetch(url);assert.equal(plain.status,401);
 const wrongServer=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:3000});
 await assert.rejects(wrongServer.fetch(url,{...config,expectedIdentityKey:new PrivateKey(4).toPublicKey().toString()}),/identity does not match/i);
 for(const mode of ['body','status','signature','identity','nonce','request-id']) {
  const corrupt=async (url,init)=>{
   const r=await fetch(url,init);if(!new Headers(init.headers).has('x-bsv-auth-request-id'))return r;
   const data=new Uint8Array(await r.arrayBuffer()),headers=new Headers(r.headers);let status=r.status;
   if(mode==='body' && data.length)data[0]^=1;
   if(mode==='status')status=201;
   if(mode==='signature'){const sig=headers.get('x-bsv-auth-signature');headers.set('x-bsv-auth-signature',sig.slice(0,-2)+(sig.endsWith('00')?'01':'00'));}
   if(mode==='identity')headers.set('x-bsv-auth-identity-key',new PrivateKey(4).toPublicKey().toString());
   if(mode==='nonce')headers.set('x-bsv-auth-nonce',Buffer.alloc(32,9).toString('base64'));
   if(mode==='request-id')headers.set('x-bsv-auth-request-id',Buffer.alloc(32,9).toString('base64'));
   return new Response(data,{status,headers});
  };
  const tampered=new AuthFetch(new ProtoWallet(client),undefined,undefined,undefined,{responseTimeoutMs:1500},corrupt);
  const expectedError=mode==='identity'?/identity does not match/i:/signature is not valid/i;
  await assert.rejects(tampered.fetch(url,config),expectedError,`tampered ${mode} must fail at verification`);
 }
 console.log('Fixed SDK AuthFetch: loopback HTTP handshake, signed GET /devices and canonical POST /listMessages with signed responses passed; plain request, replay, identity mismatch, wrong server identity and request and response tampering rejected.');
} finally {child.kill('SIGTERM');await new Promise(resolve=>child.once('exit',resolve));await rm(dir,{recursive:true,force:true});}
