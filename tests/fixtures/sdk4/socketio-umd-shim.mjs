// Test-only loader; assert the official Git UMD bytes before execution.
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const bytes=readFileSync(process.env.SOCKETIO_UMD);
if(!new Set(['bc425714aa8f2547d6939e3721ebafd3830a7562a1f6cb08acc1e794bd707954','e135466dffd976ef028000a211a6dfd4dda0f5a91af760f122585131f4ee9936']).has(createHash('sha256').update(bytes).digest('hex')))throw new Error('Unexpected Socket.IO fixture hash');
const require=createRequire(import.meta.url);
export const io=require(process.env.SOCKETIO_UMD);
