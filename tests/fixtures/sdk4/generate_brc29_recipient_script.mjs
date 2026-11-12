// Fixed SDK ProtoWallet('anyone') and P2PKH, using public test keys only.
import {writeFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
const root=process.env.SDK_SOURCE_DIR;
const {default:PrivateKey}=await import(pathToFileURL(`${root}/src/primitives/PrivateKey.ts`));
const {default:PublicKey}=await import(pathToFileURL(`${root}/src/primitives/PublicKey.ts`));
const {default:ProtoWallet}=await import(pathToFileURL(`${root}/src/wallet/ProtoWallet.ts`));
const {default:P2PKH}=await import(pathToFileURL(`${root}/src/script/templates/P2PKH.ts`));
const wallet=new ProtoWallet('anyone');
const cases=[];
for (const secret of [2,3,9,42]) for (const [prefix,suffix] of [['AQ==','Ag=='],['AA==','////'],['A'.repeat(128),'AQIDBA==']]) {
 const recipient=new PrivateKey(secret).toPublicKey().toString();
 const {publicKey}=await wallet.getPublicKey({protocolID:[2,'3241645161d8'],keyID:`${prefix} ${suffix}`,counterparty:recipient});
 const script=new P2PKH().lock(PublicKey.fromString(publicKey).toAddress()).toHex();
 cases.push({recipient,prefix,suffix,publicKey,script});
}
const anyone=(await wallet.getPublicKey({identityKey:true})).publicKey;
await writeFile(process.argv[2],JSON.stringify({source:'SDK 4.0.1 fixed 52d36a5, ProtoWallet anyone and P2PKH; synthetic public keys only',anyone,cases},null,2)+'\n');
console.log(`Generated ${cases.length} public-key and script vectors.`);
