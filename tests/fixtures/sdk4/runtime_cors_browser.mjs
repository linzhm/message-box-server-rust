// Optional real-browser CORS smoke test. Requires CHROME and MESSAGEBOX_SERVER.
import {spawn} from 'node:child_process';
import {createServer} from 'node:http';
import {createInterface} from 'node:readline';
import {mkdtemp,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {once} from 'node:events';
import assert from 'node:assert/strict';
const dir=await mkdtemp(join(tmpdir(),'messagebox-cors-browser-'));
let child, web;
try {
 const key=join(dir,'key'), config=join(dir,'config');
 await writeFile(key,'0'.repeat(63)+'3\n',{mode:0o600});
 await writeFile(config,JSON.stringify({bind:'127.0.0.1:0',dataDir:dir,identityKeyFile:key,freeBoxes:['inbox']}));
 child=spawn(process.env.MESSAGEBOX_SERVER,[config],{stdio:['ignore','pipe','inherit']});
 const line=createInterface({input:child.stdout})[Symbol.asyncIterator]();
 const ready=JSON.parse((await Promise.race([line.next(),new Promise((_,reject)=>setTimeout(()=>reject(Error('startup timeout')),10000))])).value);
 web=createServer((req,res)=>{res.writeHead(200,{'content-type':'text/html'});res.end(`<!doctype html><title>pending</title><script>
 (async()=>{try {
   const r=await fetch('http://${ready.address}/devices',{method:'GET',headers:{'X-Client-Extra':'test'}});
   if(r.status!==401 || !(await r.text()).includes('mutual-authentication failed')) throw Error('status/body mismatch');
   document.title='CORS_BROWSER_PASS';
 }catch(e){document.title='CORS_BROWSER_FAIL '+String(e)}})();
 </script>`)});
 web.listen(0,'127.0.0.1'); await once(web,'listening');
 const browser=spawn(process.env.CHROME,['--headless','--no-first-run',`--user-data-dir=${join(dir,'chrome')}`,'--virtual-time-budget=5000','--dump-dom',`http://127.0.0.1:${web.address().port}/`],{stdio:['ignore','pipe','pipe']});
 let output='',errors='';browser.stdout.on('data',d=>output+=d);browser.stderr.on('data',d=>errors+=d);
 const [code,signal]=await once(browser,'exit'); assert.equal(code,0,`Chrome exit ${code}/${signal}: ${errors}`); assert.match(output,/<title>CORS_BROWSER_PASS<\/title>/,output+'\n'+errors);
 console.log('Chrome cross-origin preflight and browser-readable 401 body passed; this is not a browser SDK signed exchange.');
} finally {
 if(web) await new Promise(resolve=>web.close(resolve));
 if(child && child.exitCode===null && child.signalCode===null){child.kill('SIGINT'); await once(child,'exit');}
 await rm(dir,{recursive:true,force:true});
}
