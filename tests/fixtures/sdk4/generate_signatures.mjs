import {pathToFileURL} from 'node:url';
const root=process.env.SDK_SOURCE_DIR;
const {default:PrivateKey}=await import(pathToFileURL(`${root}/src/primitives/PrivateKey.ts`));
const {default:ProtoWallet}=await import(pathToFileURL(`${root}/src/wallet/ProtoWallet.ts`));
const {default:Signature}=await import(pathToFileURL(`${root}/src/primitives/Signature.ts`));
const {default:Curve}=await import(pathToFileURL(`${root}/src/primitives/Curve.ts`));
const cases=[];
for (const [a,b,keyID,data] of [
 ['2','3','nonceA nonceB',[0,1,2,3,255]],
 ['1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef','fedcba0987654321fedcba0987654321fedcba0987654321fedcba098765432','shared-key-α🙂',[104,101,108,108,111]]
]) {
 const aliceKey=new PrivateKey(a,16),bobKey=new PrivateKey(b,16),alice=new ProtoWallet(aliceKey),bob=new ProtoWallet(bobKey);
 const protocolID=[2,'auth message signature'];const alicePublic=aliceKey.toPublicKey().toString(),bobPublic=bobKey.toPublicKey().toString();
 const {signature}=await alice.createSignature({data,protocolID,keyID,counterparty:bobPublic});
 const standard=await bob.verifySignature({data,signature,protocolID,keyID,counterparty:alicePublic});
 const high=Signature.fromDER(signature); high.s=new Curve().n.sub(high.s); const highBytes=high.toDER();
 const highResult=await bob.verifySignature({data,signature:highBytes,protocolID,keyID,counterparty:alicePublic});
 cases.push({a,b,keyID,invoice:`2-auth message signature-${keyID}`,data,alicePublic,bobPublic,signature:Buffer.from(signature).toString('hex'),highSignature:Buffer.from(highBytes).toString('hex'),standardValid:standard.valid,highValid:highResult.valid});
}
console.log(JSON.stringify({source:'ts-stack 52d36a5, SDK 4.0.1 ProtoWallet TypeScript source; fixed public test keys only',cases},null,2));
