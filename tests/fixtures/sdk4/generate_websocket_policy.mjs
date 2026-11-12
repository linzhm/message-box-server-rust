// Execute pinned server room and identity policy with fixed Git SDK PublicKey.
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const evidence=JSON.parse(await readFile(process.env.TS_SERVER_EVIDENCE,'utf8'));
function source(path,expected){const s=evidence.files[path].content,b=Buffer.from(s);assert.equal(createHash('sha1').update(`blob ${b.length}\0`).update(b).digest('hex'),expected);return s.replace(/import\s+[\s\S]*?\s+from\s+['"][^'"]+['"]\s*/g,'').replace(/\bexport\s+/g,'');}
const fields=source('infra/message-box-server/src/security/messageFields.ts','2430df04e5f787d5353b0f0035f50d46447e4fa4');
const policy=source('infra/message-box-server/src/security/webSocketPolicy.ts','7c09ba9e77f1afb9c283628d14952c8a6f04a4d4');
const ts=(await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
const {default:PublicKey}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/primitives/PublicKey.ts`));
const {default:PrivateKey}=await import(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/primitives/PrivateKey.ts`));
const js=ts.transpileModule(`${fields}\n${policy}\nreturn {authenticatedWebSocketIdentity,isIdentityOwnedRoom,messageBoxFromRecipientRoom};`,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const api=new Function('PublicKey',js)(PublicKey),a=new PrivateKey(2).toPublicKey(),b=new PrivateKey(3).toPublicKey().toString(),identity=a.toString(),uncompressed=a.encode(false,'hex'),hybrid=(parseInt(uncompressed.at(-1),16)%2 ? '07' : '06')+uncompressed.slice(2);
let oddPoint;for(let n=4;n<20;n++){const candidate=new PrivateKey(n).toPublicKey();if(candidate.toString().startsWith('03')){oddPoint=candidate;break}}assert.ok(oddPoint);const oddHybrid='07'+oddPoint.encode(false,'hex').slice(2);
const claims=[{transport:identity},{transport:identity,claim:identity},{transport:identity,claim:` ${identity} `},{transport:identity,claim:b},{transport:identity,claim:42},{transport:null},{transport:'not-a-key'},{transport:uncompressed},{transport:identity.toUpperCase()},{transport:identity.slice(1)},{transport:hybrid},{transport:oddHybrid},{transport:(hybrid.startsWith('06')?'07':'06')+hybrid.slice(2)}].map(input=>{try{return {input,result:api.authenticatedWebSocketIdentity(input.transport,input.claim)}}catch(e){return {input,error:e.message}}});
const rooms=[`${identity}-inbox`,`${identity}-payment_inbox`,`${b}-inbox`,`${identity}-`,`${identity}- inbox`,`${identity}-inbox\n`,`${identity}-${'x'.repeat(128)}`,`${identity}-${'x'.repeat(129)}`,`${identity}-${'猫'.repeat(42)}`,`${identity}-${'猫'.repeat(43)}`,`${identity}-box-1`,null,42,''].map(room=>({room,owned:api.isIdentityOwnedRoom(identity,room),box:api.messageBoxFromRecipientRoom(identity,room)??null}));
const recipients=[identity,identity.toUpperCase(),uncompressed,b,'nope'].map(recipient=>({recipient,room:`${recipient}-inbox`,box:api.messageBoxFromRecipientRoom(recipient,`${recipient}-inbox`)??null}));
await writeFile(process.argv[2],JSON.stringify({identity,claims,rooms,recipients},null,2)+'\n');
console.log(`Generated ${claims.length} identity, ${rooms.length} room and ${recipients.length} recipient cases from pinned server sources.`);
