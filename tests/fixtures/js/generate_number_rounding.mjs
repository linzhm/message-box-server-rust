// JSON.parse number bits from the JavaScript runtime, with no application state.
import {writeFile} from 'node:fs/promises';
const raw=['0.9999999999999999','1.0000000000000001','4634637815817395.509255768254','0','-0','1.0','1e0','-0.0','5e-324','2.2250738585072014e-308','1.7976931348623157e308','9007199254740991','9007199254740993','-9007199254740993','9223372036854775807','0.10000000000000001','2.2250738585072012e-308','1.234567890123456789'];
const cases=raw.map(input=>{const number=JSON.parse(input);const bytes=new ArrayBuffer(8);const view=new DataView(bytes);view.setFloat64(0,number,false);return {input,bits:view.getBigUint64(0,false).toString(16).padStart(16,'0')};});
await writeFile(process.argv[2],JSON.stringify({source:'JavaScript JSON.parse binary64 observations',cases},null,2)+'\n');
console.log(`Generated ${cases.length} finite JSON number observations.`);
