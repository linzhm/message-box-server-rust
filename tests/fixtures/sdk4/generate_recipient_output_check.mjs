// Fixed TS recipient-output function, fixed SDK wallet/P2PKH, synthetic tx outputs.
// The chain verifier is a stub and no transaction or payment is verified.
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const evidence=JSON.parse(await readFile(process.env.TS_SERVER_EVIDENCE,'utf8'));
const source=evidence.files['infra/message-box-server/src/routes/sendMessage.ts'].content,bytes=Buffer.from(source);
const sha=createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
assert.equal(sha,'1279ce37c009e1cc37419824673f1ac4403b0510');
const a=source.indexOf('function validDerivationToken('),b=source.indexOf('function hasCanonicalDeliveryRemittance(',a);
const c=source.indexOf('async function validateRecipientOutputs('),d=source.indexOf('function taggedRecipient(',c);
assert.ok(a>=0&&b>a&&c>=0&&d>c);
const ts=(await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
const js=ts.transpileModule(source.slice(a,b)+'\n'+source.slice(c,d)+'\nreturn validateRecipientOutputs(payment,parsed,allocated,feeRows,deliveryFee);',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const root=process.env.SDK_SOURCE_DIR;
const {default:PublicKey}=await import(pathToFileURL(`${root}/src/primitives/PublicKey.ts`));
const {default:ProtoWallet}=await import(pathToFileURL(`${root}/src/wallet/ProtoWallet.ts`));
const {default:P2PKH}=await import(pathToFileURL(`${root}/src/script/templates/P2PKH.ts`));
const {toArray,toBase64}=await import(pathToFileURL(`${root}/src/primitives/utils.ts`));
const check=new Function('payment','parsed','allocated','feeRows','deliveryFee','anyoneIdentityKey','anyoneWallet','P2PKH','PublicKey','routeFailure','verifyRecipientPaymentTransaction','toArray','toBase64','MAX_PAYMENT_DERIVATION_BYTES','BRC29_PROTOCOL_ID',js);
const f=JSON.parse(await readFile(new URL('brc29_recipient_script_vectors.json',import.meta.url),'utf8'));
const item=f.cases[0],anyone=f.anyone,recipient=item.recipient;
const rem={outputIndex:0,protocol:'wallet payment',paymentRemittance:{derivationPrefix:item.prefix,derivationSuffix:item.suffix,senderIdentityKey:anyone}};
const base={recipient,fee:10,deliveryIndex:null,outputs:[rem],transactionOutputs:[{satoshis:10,script:item.script}]};
const cases=[['exact',base],['over', {...base,transactionOutputs:[{satoshis:11,script:item.script}]}],['insufficient',{...base,transactionOutputs:[{satoshis:9,script:item.script}]}],['wrong-script',{...base,transactionOutputs:[{satoshis:10,script:'51'}]}],['no-output',{...base,transactionOutputs:[]}],['missing',{...base,outputs:[]}],['bad-protocol',{...base,outputs:[{...rem,protocol:'basket insertion'}]}],['bad-token',{...base,outputs:[{...rem,paymentRemittance:{...rem.paymentRemittance,derivationPrefix:'AB=='}}]}],['wrong-sender',{...base,outputs:[{...rem,paymentRemittance:{...rem.paymentRemittance,senderIdentityKey:recipient}}]}],['duplicate',{...base,outputs:[rem,rem]}],['server-index-reuse',{...base,deliveryIndex:0}],['two-split',{...base,outputs:[rem,{...rem,outputIndex:1}],transactionOutputs:[{satoshis:4,script:item.script},{satoshis:6,script:item.script}]}]];
const wallet=new ProtoWallet('anyone');
const results=[];
for(const [label,input] of cases){let verifierCalled=false;
 const parsed={transaction:{outputs:input.transactionOutputs.map(o=>({satoshis:o.satoshis,lockingScript:{toHex:()=>o.script}}))}};
 const result=await check({outputs:[{outputIndex:input.deliveryIndex}]},parsed,new Map([[recipient,input.outputs]]),[{recipient,recipientFee:input.fee}],input.deliveryIndex===null?0:1,async()=>anyone,wallet,P2PKH,PublicKey,(_status,code)=>({code}),async()=>{verifierCalled=true;return undefined;},toArray,toBase64,128,[2,'3241645161d8']);
 results.push({label,input,expected:result?.code??null,verifierCalled});
}
await writeFile(process.argv[2],JSON.stringify({sourceBlob:sha,cases:results},null,2)+'\n');
console.log(`Generated ${results.length} recipient-output observations; chain verification stubbed.`);
