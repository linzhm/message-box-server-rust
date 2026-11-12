// Loads pinned Git sources. Socket.IO is deliberately unavailable in this HTTP-only test.
import { access, readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
const ts = (await import(pathToFileURL(process.env.TYPESCRIPT_LIB).href)).default;
export async function resolve(specifier, context, nextResolve) {
  if (specifier === 'socket.io-client') return nextResolve(new URL('./no-socket-io.mjs', import.meta.url).href, context);
  if (specifier === '@bsv/authsocket-client') return nextResolve(pathToFileURL(`${process.env.CLIENT_SOURCE_DIR}/packages/messaging/authsocket-client/mod.ts`).href, context);
  if (specifier === '@bsv/sdk') return nextResolve(pathToFileURL(`${process.env.SDK_SOURCE_DIR}/mod.ts`).href, context);
  if (specifier.startsWith('@bsv/sdk/')) {
    const stem = `${process.env.SDK_SOURCE_DIR}/src/${specifier.slice('@bsv/sdk/'.length)}`;
    for (const path of [`${stem}.ts`, `${stem}/index.ts`]) {
      try { await access(path); return nextResolve(pathToFileURL(path).href, context); } catch {}
    }
  }
  if (specifier.startsWith('.') && specifier.endsWith('.js') && context.parentURL?.startsWith('file:')) {
    const candidate = new URL(specifier.slice(0, -3) + '.ts', context.parentURL);
    try { await access(candidate); return nextResolve(candidate.href, context); } catch {}
  }
  return nextResolve(specifier, context);
}
export async function load(url, context, nextLoad) {
  if (url.endsWith('.ts')) {
    const source = await readFile(new URL(url), 'utf8');
    return { format: 'module', shortCircuit: true, source: ts.transpileModule(source, {compilerOptions: {module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022}}).outputText };
  }
  return nextLoad(url, context);
}
