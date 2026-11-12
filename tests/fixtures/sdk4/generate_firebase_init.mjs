// Execute the fixed Firebase initializer with synthetic env/SDK/file adapters.
// No real credentials, filesystem reads or Firebase/network calls.
import {readFile,writeFile} from 'node:fs/promises';import {createHash} from 'node:crypto';import {pathToFileURL} from 'node:url';import assert from 'node:assert/strict';import path from 'node:path';
const bytes=await readFile(process.env.FIREBASE_CONFIG_SOURCE),blob=createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');assert.equal(blob,'e5871dab0061bd7970925249fd6839bf5de409fb');
let source=bytes.toString().replace(/^import\s+[\s\S]*?\s+from\s+['"][^'"]+['"]\s*/gm,'').replace(/\bexport\s+/g,'');const ts=(await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;const js=ts.transpileModule(`${source}\nreturn {initializeFirebase,getFirebaseMessaging};`,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const valid=JSON.stringify({private_key:'fake-key',client_email:'fake@example.test',project_id:'credential-project'}), scenarios=[
 {name:'disabled-unset',steps:[{}]}, {name:'disabled-variants',steps:[{ENABLE_FIREBASE:'false'},{ENABLE_FIREBASE:'TRUE'},{ENABLE_FIREBASE:' true '}]},
 {name:'missing-project',steps:[{ENABLE_FIREBASE:'true'}]}, {name:'empty-project',steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:''}]},
 {name:'whitespace-project',steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:' '}]},
 {name:'default-credentials',steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'project',FIREBASE_SERVICE_ACCOUNT_JSON:'',FIREBASE_SERVICE_ACCOUNT_PATH:''}]},
 {name:'json-precedence',steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'project',FIREBASE_SERVICE_ACCOUNT_JSON:valid,FIREBASE_SERVICE_ACCOUNT_PATH:'ignored.json'}]},
 {name:'invalid-json-no-fallback',steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'project',FIREBASE_SERVICE_ACCOUNT_JSON:'{',FIREBASE_SERVICE_ACCOUNT_PATH:'ignored.json'}]},
 {name:'missing-fields',steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'project',FIREBASE_SERVICE_ACCOUNT_JSON:'{}'}]},
 {name:'file-credential',files:{'/work/keys/service.json':valid},steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'project',FIREBASE_SERVICE_ACCOUNT_PATH:'keys/../keys/service.json'}]},
 {name:'file-absolute',files:{'/secrets/service.json':valid},steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'project',FIREBASE_SERVICE_ACCOUNT_PATH:'/secrets/other/../service.json'}]},
 {name:'file-missing',steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'project',FIREBASE_SERVICE_ACCOUNT_PATH:'missing.json'}]},
 {name:'existing-app',existing:true,steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'project',FIREBASE_SERVICE_ACCOUNT_JSON:valid}]},
 {name:'cached-and-disabled',steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'first'}, {ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'',FIREBASE_SERVICE_ACCOUNT_JSON:'{'},{ENABLE_FIREBASE:'false'}]},
 {name:'cert-failure-no-fallback',fail:'cert',steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'project',FIREBASE_SERVICE_ACCOUNT_JSON:valid,FIREBASE_SERVICE_ACCOUNT_PATH:'ignored.json'}]},
 {name:'default-failure',fail:'default',steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'project'}]},
 {name:'get-apps-failure',fail:'getApps',steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'project'}]},
 {name:'get-app-failure',existing:true,fail:'getApp',steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'project'}]},
 {name:'init-failure',fail:'init',steps:[{ENABLE_FIREBASE:'true',FIREBASE_PROJECT_ID:'project'}]}
];
function run(c){const calls=[],fakeProcess={env:{},cwd:()=>'/work'};let appCount=c.existing?1:0;function fail(name){if(c.fail===name)throw Error(`fake-${name}-failure`)}
 const api=new Function('initializeApp','getApps','getApp','cert','applicationDefault','getMessaging','getFirestore','path','readFileSync','dotenv','log','process',js)(
  ({projectId})=>{calls.push(`initialize:${projectId}`);fail('init');appCount++;return {id:'new'}},()=>{calls.push('getApps');fail('getApps');return Array(appCount).fill({})},()=>{calls.push('getApp');fail('getApp');return {id:'existing'}},({projectId})=>{calls.push(`cert:${projectId}`);fail('cert');return {credential:'cert'}},()=>{calls.push('default');fail('default');return {credential:'default'}},app=>({id:app.id}),()=>({}),path,(file)=>{calls.push(`read:${file}`);if(!(file in (c.files??{})))throw Error('fake-read-failure');return c.files[file]}, {config(){}},{info(){},error(){}},fakeProcess);
 const results=[];for(const step of c.steps){fakeProcess.env=step;try{const result=api.initializeFirebase();results.push({app:result?.id??null,error:null})}catch(error){results.push({app:null,error:error.message.includes('FIREBASE_PROJECT_ID')?'missing-project':error.message.includes('Failed to parse Firebase service account')?'invalid-credential':error.message.includes('fake-read-failure')?'read-failure':'backend-failure'})}}return {input:c,results,calls,messaging:api.getFirebaseMessaging()?.id??null};}
const cases=scenarios.map(run);await writeFile(process.argv[2],JSON.stringify({sourceBlob:blob,cases},null,2)+'\n');console.log(`Generated ${cases.length} fixed TS Firebase initializer control-flow observations with fake adapters.`);
