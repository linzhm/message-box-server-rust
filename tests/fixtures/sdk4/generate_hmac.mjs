import {pathToFileURL} from 'node:url';
const root=process.env.SDK_SOURCE_DIR;
const {default:PrivateKey}=await import(pathToFileURL(`${root}/src/primitives/PrivateKey.ts`));
const {default:ProtoWallet}=await import(pathToFileURL(`${root}/src/wallet/ProtoWallet.ts`));
const {default:KeyDeriver}=await import(pathToFileURL(`${root}/src/wallet/KeyDeriver.ts`));
const {verifyNonce}=await import(pathToFileURL(`${root}/src/auth/utils/verifyNonce.ts`));
const cases=[];
for (const [a,b,data,self,explicitKeyID] of [
 ['2','3',[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],false],
 ['1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef','1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',[239,187,191,65,255,192,128,226,130,0,66,240,159,152,128,67],true],
 ['2','3',[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],false,'leading-zero-372']
]) {
 const aliceKey=new PrivateKey(a,16),bobKey=new PrivateKey(b,16),alice=new ProtoWallet(aliceKey),bob=new ProtoWallet(bobKey);
 const keyID=explicitKeyID??new TextDecoder().decode(new Uint8Array(data)); const protocolID=[2,'server hmac'];
 const alicePublic=aliceKey.toPublicKey().toString(),bobPublic=bobKey.toPublicKey().toString();
 const {hmac}=await alice.createHmac({data,protocolID,keyID,counterparty:self?'self':bobPublic});
 const result=await bob.verifyHmac({data,hmac,protocolID,keyID,counterparty:self?'self':alicePublic});
 const nonce=Buffer.concat([Buffer.from(data),Buffer.from(hmac)]).toString('base64');
 const nonceVerified=self?await verifyNonce(nonce,alice):null;
 const keyByteLength=new KeyDeriver(aliceKey).deriveSymmetricKey(protocolID,keyID,self?'self':bobPublic).toArray().length;
 cases.push({a,b,data,keyID,keyByteLength,invoice:`2-server hmac-${keyID}`,alicePublic,bobPublic,hmac:Buffer.from(hmac).toString('hex'),valid:result.valid,nonce,nonceVerified});
}
console.log(JSON.stringify({source:'ts-stack 52d36a5, SDK 4.0.1 ProtoWallet TypeScript source; public test keys only',cases},null,2));
