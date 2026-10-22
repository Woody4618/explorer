import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { gzipSync } from 'node:zlib';

import { Agent } from 'undici';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { BrotliRejectedError, rejectBrotli } from '../reject-brotli';

// A real server, not a mocked fetch: the interceptor only matters if it fires before Node decodes the body.
describe('rejectBrotli', () => {
    let server: Server;
    let origin: string;

    beforeAll(async () => {
        server = createServer((req, res) => {
            const encoding = decodeURIComponent(req.url?.slice(1) ?? '');
            // Not a valid Brotli stream: if anything decoded it, the failure would be a decode error instead.
            const body = encoding === 'gzip' ? gzipSync('{"ok":true}') : Buffer.from('{"ok":true}');
            res.writeHead(200, encoding ? { 'content-encoding': encoding } : {});
            res.end(body);
        });
        await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
        origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    });

    afterAll(() => new Promise(resolve => server.close(resolve)));

    async function get(path: string) {
        const agent = new Agent();
        try {
            // `dispatcher` is an undici extension to RequestInit, so it is cast past the type check.
            const init = { dispatcher: agent.compose(rejectBrotli) } as RequestInit;
            const response = await fetch(`${origin}${path}`, init);
            return await response.text();
        } finally {
            await agent.close();
        }
    }

    it('should abort a Brotli-encoded response before it is decoded', async () => {
        const error = await get('/br').catch((e: unknown) => e);

        expect(error).toBeInstanceOf(Error);
        expect((error as Error).cause).toBeInstanceOf(BrotliRejectedError);
    });

    it('should abort when Brotli is one of several encodings', async () => {
        const error = await get('/gzip,%20br').catch((e: unknown) => e);

        expect((error as Error).cause).toBeInstanceOf(BrotliRejectedError);
    });

    it('should still decode a gzip response', async () => {
        await expect(get('/gzip')).resolves.toBe('{"ok":true}');
    });

    it('should pass through an unencoded response', async () => {
        await expect(get('/')).resolves.toBe('{"ok":true}');
    });
});
