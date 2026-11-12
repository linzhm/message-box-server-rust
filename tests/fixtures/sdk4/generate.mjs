import {createHmac} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const root=process.env.SDK_SOURCE_DIR;
const {createNonce}=await import(pathToFileURL(`${root}/src/auth/utils/createNonce.ts`));
const {verifyNonce}=await import(pathToFileURL(`${root}/src/auth/utils/verifyNonce.ts`));
const secret=Buffer.from('sdk-fixture-key');
const records=[];
const wallet={async createHmac(args,originator) { const mac=createHmac('sha256',secret).update(Buffer.from(args.data)).digest(); records.push({args,originator:originator??null,hmac:[...mac]}); return {hmac:[...mac]};}, async verifyHmac(args,originator) { const mac=createHmac('sha256',secret).update(Buffer.from(args.data)).digest(); records.push({args,originator:originator??null}); return {valid:mac.equals(Buffer.from(args.hmac))};}};
const cases=[];
for (const data of [Array.from({length:16},(_,i)=>i),[0xef,0xbb,0xbf,0x41,0xff,0xc0,0x80,0xe2,0x82,0,0x42,0xf0,0x9f,0x98,0x80,0x43]]) {
 const mac=createHmac('sha256',secret).update(Buffer.from(data)).digest();
 const token=Buffer.concat([Buffer.from(data),mac]).toString('base64');
 const valid=await verifyNonce(token,wallet,'self','app.example');
 const log=records.pop(); cases.push({token,data,keyId:log.args.keyID,mac:[...mac],valid,protocolID:log.args.protocolID,counterparty:log.args.counterparty,originator:log.originator});
}
const generated=await createNonce(wallet,'self','app.example'); const genLog=records.pop(); const verified=await verifyNonce(generated,wallet,'self','app.example'); records.pop();
console.log(JSON.stringify({source:'ts-stack 52d36a5, packages/sdk 4.0.1 TypeScript source, transpileModule 5.0.2; fake HMAC wallet for codec fixture only',cases,generated:{token:generated,verified,data:genLog.args.data,keyId:genLog.args.keyID,mac:genLog.hmac}},null,2));
