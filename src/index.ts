#!/usr/bin/env node
import {loadConfig} from './config.js';
import {OidcClient} from './oidc-client.js';
import {GatewayOAuthProvider} from './oauth-provider.js';
import {TokenStore} from './token-store.js';
import {UpstreamManager} from './upstream-manager.js';
import {createApp} from './server.js';

const main = () => {
	const config = loadConfig();
	const store = new TokenStore(config.storage);
	const oidcClient = new OidcClient(config.auth);
	const provider = new GatewayOAuthProvider(oidcClient, config);
	const upstreamManager = new UpstreamManager(config, store);
	const app = createApp(config, provider, oidcClient, store, upstreamManager);

	const port = config.port ?? 3000;
	const host = config.host ?? '0.0.0.0';
	const server = app.listen(port, host, () => {
		console.log(`mcp-gateway listening on ${host}:${port}`);
		console.log(`Auth: ${config.auth.issuer}`);
		console.log(`Upstreams: ${config.upstreams.map((u) => u.name).join(', ')}`);
		console.log(`Storage: ${config.storage ?? 'memory'}`);
	});

	const shutdown = () => {
		console.log('\nShutting down...');
		server.close();
		store.close();
		process.exit(0);
	};

	process.on('SIGINT', shutdown);
	process.on('SIGTERM', shutdown);
};

main();
