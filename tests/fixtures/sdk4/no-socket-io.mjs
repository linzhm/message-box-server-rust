// Explicit fail-closed stand-in: this HTTP-only test cannot exercise Socket.IO.
export function io() { throw new Error('Socket.IO is unavailable in this HTTP-only test'); }
export class Socket { constructor() { throw new Error('Socket.IO is unavailable in this HTTP-only test'); } }
