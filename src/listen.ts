import type {Server} from 'node:http';

/** Bound when no host is configured. Accepts IPv6 and IPv4 on Linux. */
export const DEFAULT_HOST = '::';
/** Used only when the kernel has no IPv6 at all. */
export const IPV4_HOST = '0.0.0.0';

/**
 * Bind dual-stack by default.
 *
 * `0.0.0.0` is IPv4-only. On a dual-stack cluster ingress-nginx tries a pod's
 * IPv6 address first, so with that default every request paid a refused
 * connect and a retry (93% of requests on Adam's homelab, 2026-08-23). `::`
 * accepts both families. A host with IPv6 disabled rejects it with
 * EAFNOSUPPORT, and only then is IPv4 bound instead - any other error, or any
 * error on an explicitly configured host, is fatal.
 */
export const listen = async (
	server: Pick<Server, 'listen' | 'once' | 'off'>,
	port: number,
	host: string | undefined,
	log: (message: string) => void = console.log,
): Promise<string> => new Promise((resolve, reject) => {
	const bind = (candidate: string, allowFallback: boolean) => {
		const onError = (error: NodeJS.ErrnoException) => {
			if (allowFallback && error.code === 'EAFNOSUPPORT') {
				log(`IPv6 unavailable (${error.code}), binding ${IPV4_HOST} instead`);
				bind(IPV4_HOST, false);
				return;
			}

			reject(error);
		};

		server.once('error', onError);
		server.listen(port, candidate, () => {
			server.off('error', onError);
			resolve(candidate);
		});
	};

	if (host) {
		bind(host, false);
	} else {
		bind(DEFAULT_HOST, true);
	}
});
