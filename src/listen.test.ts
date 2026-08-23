import {EventEmitter} from 'node:events';
import {createServer, type Server} from 'node:http';
import {
	afterEach, describe, expect, test,
} from 'vitest';
import {DEFAULT_HOST, IPV4_HOST, listen} from './listen.js';

const servers: Server[] = [];
afterEach(async () => {
	await Promise.all(servers.splice(0).map(async (s) => new Promise<void>((resolve) => {
		s.close(() => {
			resolve();
		});
	})));
});

/** A server whose listen() fails with the given code for the given host. */
const fakeServer = (failing: Record<string, string>) => {
	const emitter = new EventEmitter();
	const bound: string[] = [];
	const server = {
		bound,
		once: emitter.once.bind(emitter),
		off: emitter.off.bind(emitter),
		listen(_port: number, host: string, cb: () => void) {
			const code = failing[host];
			if (code) {
				const error = new Error(code) as NodeJS.ErrnoException;
				error.code = code;
				setImmediate(() => emitter.emit('error', error));
			} else {
				bound.push(host);
				setImmediate(cb);
			}

			return server;
		},
	};
	return server as unknown as Pick<Server, 'listen' | 'once' | 'off'> & {bound: string[]};
};

describe('listen', () => {
	test('binds :: by default', async () => {
		const server = createServer();
		servers.push(server);
		await expect(listen(server, 0, undefined)).resolves.toBe(DEFAULT_HOST);
	});

	test('uses an explicit host as given', async () => {
		const server = createServer();
		servers.push(server);
		await expect(listen(server, 0, '127.0.0.1')).resolves.toBe('127.0.0.1');
	});

	test('falls back to IPv4 only when the kernel has no IPv6', async () => {
		const logs: string[] = [];
		const server = fakeServer({'::': 'EAFNOSUPPORT'});
		await expect(listen(server, 3000, undefined, (m) => logs.push(m))).resolves.toBe(IPV4_HOST);
		expect(server.bound).toEqual([IPV4_HOST]);
		expect(logs[0]).toContain('EAFNOSUPPORT');
	});

	test('any other error is fatal', async () => {
		const server = fakeServer({'::': 'EADDRINUSE'});
		await expect(listen(server, 3000, undefined)).rejects.toMatchObject({code: 'EADDRINUSE'});
	});

	test('an explicit host never falls back', async () => {
		const server = fakeServer({'::': 'EAFNOSUPPORT'});
		await expect(listen(server, 3000, '::')).rejects.toMatchObject({code: 'EAFNOSUPPORT'});
	});
});
