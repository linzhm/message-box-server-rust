import { access, readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
const ts = (await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
export async function resolve(specifier, context, nextResolve) {
  if (specifier === '@bsv/sdk/primitives/utils') return nextResolve(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/primitives/utils.ts`).href, context);
  if (specifier === '@bsv/sdk') return nextResolve(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/src/wallet/BRC100ByteEncoding.ts`).href, context);
  if (specifier.startsWith('.') && specifier.endsWith('.js') && context.parentURL?.startsWith('file:')) {
    const candidate = new URL(specifier.slice(0,-3) + '.ts', context.parentURL);
    try { await access(candidate); return nextResolve(candidate.href, context); } catch {}
  }
  return nextResolve(specifier, context);
}
export async function load(url, context, nextLoad) {
  if (url.endsWith('.ts')) {
    const source = await readFile(new URL(url), 'utf8');
    return { format:'module', shortCircuit:true, source:ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ES2022,target:ts.ScriptTarget.ES2022}}).outputText };
  }
  return nextLoad(url, context);
}
