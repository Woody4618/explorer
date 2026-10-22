import type { Dispatcher } from 'undici';

/** Raised through the dispatcher so `fetch` rejects before Node's Brotli decoder sees a single byte. */
export class BrotliRejectedError extends Error {
    constructor() {
        super('Upstream responded with Content-Encoding: br');
        this.name = 'BrotliRejectedError';
    }
}

/**
 * Dispatcher interceptor that aborts any response encoded with Brotli.
 *
 * The proxy fetches URLs taken from on-chain metadata, so the upstream is attacker-controlled, and Node's
 * `fetch` decodes whatever `Content-Encoding` the server sends, whatever `Accept-Encoding` asked for. That
 * made Node's bundled Brotli decoder reachable from untrusted input (CVE-2026-111497, fixed in Node
 * 22.23.4 / 24.22.1 / 26.12.1). The check has to sit at the dispatcher: by the time `fetch` returns a
 * Response, the decoder is already consuming the body. Metadata is JSON or an image, so refusing `br`
 * costs nothing. Kept after the patch as defence in depth.
 */
export const rejectBrotli: Dispatcher.DispatchInterceptor = dispatch => (options, handler) => {
    let abort: ((err?: Error) => void) | undefined;

    // Forwards undici's extra `context` argument, which the public handler type does not declare.
    const onConnect = (abortFn: (err?: Error) => void, ...rest: unknown[]) => {
        abort = abortFn;
        (handler.onConnect as ((...args: unknown[]) => void) | undefined)?.(abortFn, ...rest);
    };

    // Every callback forwards to `handler` so its state stays on the original object.
    return dispatch(options, {
        onBodySent: (chunkSize, totalBytesSent) => handler.onBodySent?.(chunkSize, totalBytesSent),
        onComplete: trailers => handler.onComplete?.(trailers),
        onConnect,
        onData: chunk => handler.onData?.(chunk) ?? true,
        onError: error => handler.onError?.(error),
        onHeaders: (statusCode, headers, resume, statusText) => {
            if (hasBrotliEncoding(headers)) {
                abort?.(new BrotliRejectedError());
                return false;
            }
            return handler.onHeaders?.(statusCode, headers, resume, statusText) ?? true;
        },
        onResponseStarted: () => handler.onResponseStarted?.(),
        onUpgrade: (statusCode, headers, socket) => handler.onUpgrade?.(statusCode, headers, socket),
    });
};

// `headers` is a flat [name, value, name, value, …] list of Buffers (or strings).
function hasBrotliEncoding(headers: readonly (Buffer | string)[] | null): boolean {
    if (!headers) return false;
    for (let i = 0; i < headers.length; i += 2) {
        if (headers[i].toString().toLowerCase() !== 'content-encoding') continue;
        // The header is a comma-separated list, e.g. `gzip, br`.
        const encodings = headers[i + 1].toString().toLowerCase().split(',');
        if (encodings.some(encoding => encoding.trim() === 'br')) return true;
    }
    return false;
}
