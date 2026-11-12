// Run the existing fixed SDK loopback scenario with Origin attached. Node does
// not enforce CORS; this checks SDK authentication and actual response headers.
import assert from 'node:assert/strict';
const fetchOriginal = globalThis.fetch;
let signedResponses = 0;
globalThis.fetch = async (url, options = {}) => {
  const headers = new Headers(options.headers);
  headers.set('Origin', 'https://browser.example');
  const response = await fetchOriginal(url, {...options, headers});
  assert.equal(response.headers.get('access-control-allow-origin'), '*');
  if (response.headers.has('x-bsv-auth-signature')) {
    const exposed = response.headers.get('access-control-expose-headers').toLowerCase().split(',').map(x => x.trim());
    assert.ok(exposed.includes('x-bsv-auth-signature'));
    assert.ok(exposed.includes('x-bsv-auth-identity-key'));
    signedResponses++;
  }
  return response;
};
try {
  await import('./runtime_client_interop.mjs');
  assert.ok(signedResponses > 0, 'expected a signed response');
  console.log(`CORS headers observed on ${signedResponses} SDK signed responses (Node; no browser CORS enforcement).`);
} finally { globalThis.fetch = fetchOriginal; }
