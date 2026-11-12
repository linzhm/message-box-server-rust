import {pathToFileURL} from 'node:url';
const root = process.env.SDK_SOURCE_DIR;
const {default: PrivateKey} = await import(pathToFileURL(`${root}/src/primitives/PrivateKey.ts`));
const cases=[];
for (const [a,b,invoice] of [[2,3,'2-auth message signature-test'],[1,1,'2-server hmac-hello'],[17,23,'2-auth message signature-α🙂']]) {
 const alice=new PrivateKey(a), bob=new PrivateKey(b);
 const derived=alice.deriveChild(bob.toPublicKey(),invoice);
 const receiver=alice.toPublicKey().deriveChild(bob,invoice);
 cases.push({a,b,invoice,alicePublic:alice.toPublicKey().toString(),bobPublic:bob.toPublicKey().toString(),derivedPrivate:derived.toHex(64),derivedPublic:derived.toPublicKey().toString(),receiverDerivedPublic:receiver.toString()});
}
console.log(JSON.stringify({source:'ts-stack 52d36a5, packages/sdk 4.0.1 TypeScript source, transpileModule 5.0.2; small public test keys only',cases},null,2));
