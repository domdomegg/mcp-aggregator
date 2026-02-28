import {createServer, type Server as HttpServer} from 'node:http';
import {createHash, randomBytes, randomUUID} from 'node:crypto';
import {SignJWT, exportJWK, generateKeyPair} from 'jose';
import express from 'express';
import {
	afterAll, beforeAll, describe, expect, test,
} from 'vitest';
import {TokenStore} from './token-store.js';
import {OidcClient} from './oidc-client.js';
import {GatewayOAuthProvider} from './oauth-provider.js';
import {UpstreamManager} from './upstream-manager.js';
import {createApp} from './server.js';
import type {GatewayConfig} from './types.js';
import {createMockUpstream, type MockUpstream} from './mock-upstream.fixture.js';

// Mock OIDC provider (same pattern as mcp-auth-wrapper)
let oidcPrivateKey: CryptoKey;
let oidcPublicKey: CryptoKey;
let oidcServer: HttpServer;
let oidcUrl: string;

// Mock upstreams
let publicUpstream: MockUpstream;
let oauthUpstream: MockUpstream;

// Gateway
let gatewayServer: HttpServer;
let gatewayUrl: string;
let store: TokenStore;

const signIdToken = async (sub: string, issuer: string, audience: string) =>
	new SignJWT({sub})
		.setProtectedHeader({alg: 'RS256', kid: 'test-key'})
		.setIssuer(issuer)
		.setAudience(audience)
		.setIssuedAt()
		.setExpirationTime('1h')
		.sign(oidcPrivateKey);

const createMockOidc = async (): Promise<{server: HttpServer; url: string}> => {
	const keyPair = await generateKeyPair('RS256');
	oidcPrivateKey = keyPair.privateKey;
	oidcPublicKey = keyPair.publicKey;

	const app = express();
	app.use(express.urlencoded({extended: false}));

	const codes = new Map<string, {redirectUri: string; state: string | undefined; sub: string}>();

	app.get('/.well-known/openid-configuration', (_req, res) => {
		res.json({
			issuer: oidcUrl,
			authorization_endpoint: `${oidcUrl}/authorize`,
			token_endpoint: `${oidcUrl}/token`,
			jwks_uri: `${oidcUrl}/jwks`,
		});
	});

	app.get('/jwks', async (_req, res) => {
		const jwk = await exportJWK(oidcPublicKey);
		jwk.alg = 'RS256';
		jwk.kid = 'test-key';
		jwk.use = 'sig';
		res.json({keys: [jwk]});
	});

	app.get('/authorize', (req, res) => {
		const redirectUri = req.query.redirect_uri as string;
		const state = req.query.state as string | undefined;
		const code = randomUUID();
		codes.set(code, {redirectUri, state, sub: 'adam'});
		const url = new URL(redirectUri);
		url.searchParams.set('code', code);
		if (state) {
			url.searchParams.set('state', state);
		}

		res.redirect(url.toString());
	});

	app.post('/token', async (req, res) => {
		const code = req.body.code as string;
		const codeData = codes.get(code);
		if (!codeData) {
			res.status(400).json({error: 'invalid_grant'});
			return;
		}

		codes.delete(code);
		const idToken = await signIdToken(codeData.sub, oidcUrl, req.body.client_id as string);
		res.json({
			access_token: randomUUID(),
			token_type: 'bearer',
			expires_in: 3600,
			id_token: idToken,
		});
	});

	const server = createServer(app);
	await new Promise<void>((resolve) => {
		server.listen(0, '127.0.0.1', resolve);
	});

	const addr = server.address();
	if (!addr || typeof addr === 'string') {
		throw new Error('Failed to start mock OIDC');
	}

	return {server, url: `http://127.0.0.1:${addr.port}`};
};

beforeAll(async () => {
	// 1. Mock OIDC provider
	const oidc = await createMockOidc();
	oidcServer = oidc.server;
	oidcUrl = oidc.url;

	// 2. Mock upstreams
	publicUpstream = await createMockUpstream({name: 'public-server'});
	oauthUpstream = await createMockUpstream({name: 'oauth-server', requireAuth: true});

	// 3. Gateway config
	const config: GatewayConfig = {
		auth: {
			issuer: oidcUrl,
			clientId: 'test-gateway',
			clientSecret: 'test-secret',
		},
		upstreams: [
			{name: 'public-server', url: `${publicUpstream.url}/mcp`},
			{name: 'oauth-server', url: `${oauthUpstream.url}/mcp`},
		],
		storage: 'memory',
		secret: 'test-secret-key-for-sealing',
	};

	store = new TokenStore(config.storage);
	const oidcClient = new OidcClient(config.auth);
	const provider = new GatewayOAuthProvider(oidcClient, config);
	const upstreamManager = new UpstreamManager(config, store);
	const app = createApp(config, provider, oidcClient, store, upstreamManager);

	gatewayServer = createServer(app);
	await new Promise<void>((resolve) => {
		gatewayServer.listen(0, '127.0.0.1', resolve);
	});

	const addr = gatewayServer.address();
	if (!addr || typeof addr === 'string') {
		throw new Error('Failed to start gateway');
	}

	gatewayUrl = `http://127.0.0.1:${addr.port}`;
	config.issuerUrl = gatewayUrl;
}, 30_000);

afterAll(async () => {
	store.close();
	const closeServer = async (s: HttpServer) => new Promise<void>((resolve, reject) => {
		s.close((err) => {
			if (err) {
				reject(err);
			} else {
				resolve();
			}
		});
	});
	await Promise.all([
		closeServer(gatewayServer),
		closeServer(oidcServer),
		publicUpstream.close(),
		oauthUpstream.close(),
	]);
}, 15_000);

// Helper: PKCE pair
const generatePkce = () => {
	const codeVerifier = randomBytes(32).toString('base64url');
	const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
	return {codeVerifier, codeChallenge};
};

// Helper: full OAuth flow → access token
const getAccessToken = async (): Promise<string> => {
	const {codeVerifier, codeChallenge} = generatePkce();

	// Register client
	const registerRes = await fetch(`${gatewayUrl}/register`, {
		method: 'POST',
		headers: {'Content-Type': 'application/json'},
		body: JSON.stringify({
			redirect_uris: ['http://localhost:9999/callback'],
			client_name: 'test-e2e',
			token_endpoint_auth_method: 'none',
		}),
	});
	expect(registerRes.status).toBe(201);
	const clientInfo = await registerRes.json() as {client_id: string};

	// Authorize (follow redirects manually)
	const authorizeUrl = new URL(`${gatewayUrl}/authorize`);
	authorizeUrl.searchParams.set('client_id', clientInfo.client_id);
	authorizeUrl.searchParams.set('redirect_uri', 'http://localhost:9999/callback');
	authorizeUrl.searchParams.set('response_type', 'code');
	authorizeUrl.searchParams.set('code_challenge', codeChallenge);
	authorizeUrl.searchParams.set('code_challenge_method', 'S256');
	authorizeUrl.searchParams.set('state', 'test-state');

	let res = await fetch(authorizeUrl.toString(), {redirect: 'manual'});
	expect(res.status).toBe(302);

	let location = res.headers.get('location')!;
	while (location && !location.startsWith('http://localhost:9999')) {
		res = await fetch(location, {redirect: 'manual'}); // eslint-disable-line no-await-in-loop
		location = res.headers.get('location') ?? '';
	}

	const callbackUrl = new URL(location);
	const code = callbackUrl.searchParams.get('code')!;
	expect(code).toBeTruthy();
	expect(callbackUrl.searchParams.get('state')).toBe('test-state');

	// Exchange code for token
	const tokenRes = await fetch(`${gatewayUrl}/token`, {
		method: 'POST',
		headers: {'Content-Type': 'application/x-www-form-urlencoded'},
		body: new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			client_id: clientInfo.client_id,
			code_verifier: codeVerifier,
			redirect_uri: 'http://localhost:9999/callback',
		}).toString(),
	});
	expect(tokenRes.status).toBe(200);
	const tokenData = await tokenRes.json() as {access_token: string};
	expect(tokenData.access_token).toBeTruthy();
	return tokenData.access_token;
};

// Helper: MCP JSON-RPC call
const mcpCall = async (token: string, method: string, params: Record<string, unknown> = {}, id = 1) => {
	const res = await fetch(`${gatewayUrl}/mcp`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Accept: 'application/json, text/event-stream',
			Authorization: `Bearer ${token}`,
		},
		body: JSON.stringify({
			jsonrpc: '2.0', method, id, params,
		}),
	});
	return res;
};

describe('OAuth discovery', () => {
	test('serves authorization server metadata', async () => {
		const res = await fetch(`${gatewayUrl}/.well-known/oauth-authorization-server`);
		expect(res.status).toBe(200);
		const metadata = await res.json() as Record<string, unknown>;
		expect(metadata.authorization_endpoint).toBeTruthy();
		expect(metadata.token_endpoint).toBeTruthy();
		expect(metadata.registration_endpoint).toBeTruthy();
	});

	test('serves protected resource metadata', async () => {
		// RFC 9728: /.well-known/oauth-protected-resource{resource-path}
		const res = await fetch(`${gatewayUrl}/.well-known/oauth-protected-resource/mcp`);
		expect(res.status).toBe(200);
		const metadata = await res.json() as Record<string, unknown>;
		expect(metadata.resource).toBeTruthy();
	});
});

describe('unauthenticated requests', () => {
	test('rejects /mcp without token with 401', async () => {
		const res = await fetch(`${gatewayUrl}/mcp`, {
			method: 'POST',
			headers: {'Content-Type': 'application/json'},
			body: JSON.stringify({
				jsonrpc: '2.0', method: 'initialize', id: 1, params: {protocolVersion: '2025-03-26', capabilities: {}, clientInfo: {name: 'test', version: '1.0.0'}},
			}),
		});
		expect(res.status).toBe(401);
	});

	test('rejects /mcp with invalid token', async () => {
		const res = await fetch(`${gatewayUrl}/mcp`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: 'Bearer not-a-real-token',
			},
			body: JSON.stringify({
				jsonrpc: '2.0', method: 'initialize', id: 1, params: {protocolVersion: '2025-03-26', capabilities: {}, clientInfo: {name: 'test', version: '1.0.0'}},
			}),
		});
		expect(res.status).toBe(401);
	});
});

describe('full OAuth flow + tool aggregation', () => {
	test('can auth, list tools (namespaced), and call a tool on public upstream', async () => {
		const token = await getAccessToken();

		// Initialize
		const initRes = await mcpCall(token, 'initialize', {
			protocolVersion: '2025-03-26',
			capabilities: {},
			clientInfo: {name: 'test', version: '1.0.0'},
		});
		expect(initRes.status).toBe(200);

		// List tools
		const toolsRes = await mcpCall(token, 'tools/list', {}, 2);
		expect(toolsRes.status).toBe(200);
		const toolsBody = await toolsRes.json() as {result: {tools: {name: string}[]}};
		const toolNames = toolsBody.result.tools.map((t) => t.name);

		// Should have namespaced tools from public upstream
		expect(toolNames).toContain('public-server__echo');
		expect(toolNames).toContain('public-server__ping');
		expect(toolNames).toContain('public-server__get_server_name');

		// Should have meta tool
		expect(toolNames).toContain('gateway__status');

		// Call public-server__ping
		const pingRes = await mcpCall(token, 'tools/call', {name: 'public-server__ping', arguments: {}}, 3);
		expect(pingRes.status).toBe(200);
		const pingBody = await pingRes.json() as {result: {content: {text: string}[]}};
		expect(pingBody.result.content[0]!.text).toBe('pong');

		// Call public-server__echo
		const echoRes = await mcpCall(token, 'tools/call', {name: 'public-server__echo', arguments: {message: 'hello gateway'}}, 4);
		expect(echoRes.status).toBe(200);
		const echoBody = await echoRes.json() as {result: {content: {text: string}[]}};
		expect(echoBody.result.content[0]!.text).toBe('hello gateway');

		// Call public-server__get_server_name
		const nameRes = await mcpCall(token, 'tools/call', {name: 'public-server__get_server_name', arguments: {}}, 5);
		expect(nameRes.status).toBe(200);
		const nameBody = await nameRes.json() as {result: {content: {text: string}[]}};
		expect(nameBody.result.content[0]!.text).toBe('public-server');
	}, 30_000);
});

describe('gateway__status meta tool', () => {
	test('shows upstream auth statuses', async () => {
		const token = await getAccessToken();

		// Initialize first
		await mcpCall(token, 'initialize', {
			protocolVersion: '2025-03-26',
			capabilities: {},
			clientInfo: {name: 'test', version: '1.0.0'},
		});

		const res = await mcpCall(token, 'tools/call', {name: 'gateway__status', arguments: {}}, 2);
		expect(res.status).toBe(200);
		const body = await res.json() as {result: {content: {text: string}[]}};
		const statuses = JSON.parse(body.result.content[0]!.text) as {
			name: string;
			authenticated: boolean;
			authUrl?: string;
		}[];

		// Public server should show as authenticated (no auth needed)
		const publicStatus = statuses.find((s) => s.name === 'public-server');
		expect(publicStatus?.authenticated).toBe(true);

		// OAuth server should be detected as requiring auth via RFC 9728 discovery
		const oauthStatus = statuses.find((s) => s.name === 'oauth-server');
		expect(oauthStatus?.authenticated).toBe(false);
		expect(oauthStatus?.authUrl).toBeTruthy();
	}, 30_000);
});

describe('upstream OAuth token management', () => {
	test('shows authenticated and allows tool calls after token is stored', async () => {
		const token = await getAccessToken();

		// Pre-seed a valid upstream token (must be one the mock upstream accepts)
		const upstreamToken = oauthUpstream.issueToken();
		store.upsertToken('adam', 'oauth-server', {
			access_token: upstreamToken,
			token_type: 'bearer',
			expires_in: 3600,
		});

		// Initialize
		await mcpCall(token, 'initialize', {
			protocolVersion: '2025-03-26',
			capabilities: {},
			clientInfo: {name: 'test', version: '1.0.0'},
		});

		// gateway__status should show oauth-server as authenticated
		const statusRes = await mcpCall(token, 'tools/call', {name: 'gateway__status', arguments: {}}, 2);
		expect(statusRes.status).toBe(200);
		const statusBody = await statusRes.json() as {result: {content: {text: string}[]}};
		const statuses = JSON.parse(statusBody.result.content[0]!.text) as {name: string; authenticated: boolean}[];
		const oauthStatus = statuses.find((s) => s.name === 'oauth-server');
		expect(oauthStatus?.authenticated).toBe(true);

		// Should be able to call tools on the oauth upstream with the stored token
		const nameRes = await mcpCall(token, 'tools/call', {name: 'oauth-server__get_server_name', arguments: {}}, 3);
		expect(nameRes.status).toBe(200);
		const nameBody = await nameRes.json() as {result: {content: {text: string}[]}};
		expect(nameBody.result.content[0]!.text).toBe('oauth-server');
	}, 30_000);

	test('gateway__unauth removes stored token and tool calls require re-auth', async () => {
		const token = await getAccessToken();

		// Seed a valid upstream token
		const upstreamToken = oauthUpstream.issueToken();
		store.upsertToken('adam', 'oauth-server', {
			access_token: upstreamToken,
			token_type: 'bearer',
			expires_in: 3600,
		});

		await mcpCall(token, 'initialize', {
			protocolVersion: '2025-03-26',
			capabilities: {},
			clientInfo: {name: 'test', version: '1.0.0'},
		});

		// Confirm authenticated
		const statusBefore = await mcpCall(token, 'tools/call', {name: 'gateway__status', arguments: {}}, 2);
		const beforeBody = await statusBefore.json() as {result: {content: {text: string}[]}};
		const beforeStatuses = JSON.parse(beforeBody.result.content[0]!.text) as {name: string; authenticated: boolean}[];
		expect(beforeStatuses.find((s) => s.name === 'oauth-server')?.authenticated).toBe(true);

		// Unauth
		const unauthRes = await mcpCall(token, 'tools/call', {name: 'gateway__unauth', arguments: {upstream: 'oauth-server'}}, 3);
		expect(unauthRes.status).toBe(200);
		const unauthBody = await unauthRes.json() as {result: {content: {text: string}[]}};
		expect(unauthBody.result.content[0]!.text).toContain('oauth-server');

		// Confirm now unauthenticated
		const statusAfter = await mcpCall(token, 'tools/call', {name: 'gateway__status', arguments: {}}, 4);
		const afterBody = await statusAfter.json() as {result: {content: {text: string}[]}};
		const afterStatuses = JSON.parse(afterBody.result.content[0]!.text) as {name: string; authenticated: boolean; authUrl?: string}[];
		const afterOauth = afterStatuses.find((s) => s.name === 'oauth-server');
		expect(afterOauth?.authenticated).toBe(false);
		expect(afterOauth?.authUrl).toBeTruthy();

		// Tool call should now return an auth-required error
		const callRes = await mcpCall(token, 'tools/call', {name: 'oauth-server__ping', arguments: {}}, 5);
		const callBody = await callRes.json() as {result: {content: {text: string}[]; isError: boolean}};
		expect(callBody.result.isError).toBe(true);
		expect(callBody.result.content[0]!.text).toContain('Authentication required');
	}, 30_000);

	test('refreshes expired upstream token automatically', async () => {
		const token = await getAccessToken();

		// Seed an expired access token with a valid refresh token
		// expires_in of -200 sets expires_at 200s in the past, past the 60s buffer in isTokenExpired
		const refreshToken = oauthUpstream.issueRefreshToken();
		store.upsertToken('adam', 'oauth-server', {
			access_token: 'expired-access-token',
			refresh_token: refreshToken,
			token_type: 'bearer',
			expires_in: -200,
		});

		await mcpCall(token, 'initialize', {
			protocolVersion: '2025-03-26',
			capabilities: {},
			clientInfo: {name: 'test', version: '1.0.0'},
		});

		// Tool call should succeed — gateway should refresh transparently
		const res = await mcpCall(token, 'tools/call', {name: 'oauth-server__ping', arguments: {}}, 2);
		expect(res.status).toBe(200);
		const body = await res.json() as {result: {content: {text: string}[]; isError?: boolean}};
		expect(body.result.isError).toBeFalsy();
		expect(body.result.content[0]!.text).toBe('pong');
	}, 30_000);
});

describe('full upstream OAuth browser flow', () => {
	test('can auth an upstream end-to-end via browser redirect flow', async () => {
		const token = await getAccessToken();

		// Ensure no token seeded — oauth-server should be unauthenticated
		store.deleteToken('adam', 'oauth-server');

		await mcpCall(token, 'initialize', {
			protocolVersion: '2025-03-26',
			capabilities: {},
			clientInfo: {name: 'test', version: '1.0.0'},
		});

		// Get authUrl from gateway__status
		const statusRes = await mcpCall(token, 'tools/call', {name: 'gateway__status', arguments: {}}, 2);
		const statusBody = await statusRes.json() as {result: {content: {text: string}[]}};
		const statuses = JSON.parse(statusBody.result.content[0]!.text) as {name: string; authenticated: boolean; authUrl?: string}[];
		const oauthStatus = statuses.find((s) => s.name === 'oauth-server');
		expect(oauthStatus?.authenticated).toBe(false);
		const authUrl = oauthStatus?.authUrl;
		expect(authUrl).toBeTruthy();

		// Follow the full browser flow: /upstream-auth/start → upstream /authorize → /upstream-auth/callback
		// The mock upstream auto-approves, so we just follow redirects until we hit the success page
		let res = await fetch(authUrl!, {redirect: 'manual'});
		while (res.status === 302) {
			const location = res.headers.get('location')!;
			// eslint-disable-next-line no-await-in-loop
			res = await fetch(location, {redirect: 'manual'});
		}

		// Final response should be the success page (200)
		expect(res.status).toBe(200);
		const body = await res.text();
		expect(body).toContain('oauth-server');

		// Now the token should be stored — tool call should succeed
		const callRes = await mcpCall(token, 'tools/call', {name: 'oauth-server__ping', arguments: {}}, 3);
		expect(callRes.status).toBe(200);
		const callBody = await callRes.json() as {result: {content: {text: string}[]; isError?: boolean}};
		expect(callBody.result.isError).toBeFalsy();
		expect(callBody.result.content[0]!.text).toBe('pong');
	}, 30_000);
});

describe('upstream auto-detection', () => {
	test('tool call on unauthenticated oauth upstream auto-detects and returns auth required', async () => {
		const token = await getAccessToken();

		// Ensure no stored token
		store.deleteToken('adam', 'oauth-server');

		await mcpCall(token, 'initialize', {
			protocolVersion: '2025-03-26',
			capabilities: {},
			clientInfo: {name: 'test', version: '1.0.0'},
		});

		// Cold call — no token, no prior discovery. Gateway should try unauthenticated,
		// get a 401, discover OAuth metadata, and return auth-required error.
		const res = await mcpCall(token, 'tools/call', {name: 'oauth-server__ping', arguments: {}}, 2);
		expect(res.status).toBe(200);
		const body = await res.json() as {result: {content: {text: string}[]; isError?: boolean}};
		expect(body.result.isError).toBe(true);
		expect(body.result.content[0]!.text).toContain('Authentication required');
	}, 30_000);
});

// Helper: spin up a gateway instance pointing at a custom upstream server, run a callback, then clean up.
const withTestGateway = async (
	upstreamServer: HttpServer,
	upstreamName: string,
	configOverrides: Partial<GatewayConfig>,
	fn: (mcpCallFn: (method: string, params?: Record<string, unknown>, id?: number) => Promise<Response>) => Promise<void>,
) => {
	const addr = upstreamServer.address() as {port: number};
	const config: GatewayConfig = {
		auth: {issuer: oidcUrl, clientId: 'test-gateway', clientSecret: 'test-secret'},
		upstreams: [{name: upstreamName, url: `http://127.0.0.1:${addr.port}/mcp`}],
		storage: 'memory',
		secret: 'test-secret-key-for-sealing',
		...configOverrides,
	};

	const testStore = new TokenStore('memory');
	const oidcClient = new OidcClient(config.auth);
	const provider = new GatewayOAuthProvider(oidcClient, config);
	const upstreamManager = new UpstreamManager(config, testStore);
	const app = createApp(config, provider, oidcClient, testStore, upstreamManager);

	const gw = createServer(app);
	await new Promise<void>((resolve) => {
		gw.listen(0, '127.0.0.1', resolve);
	});
	const gwAddr = gw.address() as {port: number};
	const gwUrl = `http://127.0.0.1:${gwAddr.port}`;
	config.issuerUrl = gwUrl;

	try {
		// Get an access token for this gateway
		const {codeVerifier, codeChallenge} = generatePkce();
		const regRes = await fetch(`${gwUrl}/register`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({redirect_uris: ['http://localhost:9999/callback'], token_endpoint_auth_method: 'none'})});
		const {client_id: clientId} = await regRes.json() as {client_id: string};
		const authUrlR = new URL(`${gwUrl}/authorize`);
		authUrlR.searchParams.set('client_id', clientId);
		authUrlR.searchParams.set('redirect_uri', 'http://localhost:9999/callback');
		authUrlR.searchParams.set('response_type', 'code');
		authUrlR.searchParams.set('code_challenge', codeChallenge);
		authUrlR.searchParams.set('code_challenge_method', 'S256');
		let r = await fetch(authUrlR.toString(), {redirect: 'manual'});
		let loc = r.headers.get('location')!;
		while (loc && !loc.startsWith('http://localhost:9999')) {
			// eslint-disable-next-line no-await-in-loop
			r = await fetch(loc, {redirect: 'manual'});
			loc = r.headers.get('location') ?? '';
		}

		const code = new URL(loc).searchParams.get('code')!;
		const tokRes = await fetch(`${gwUrl}/token`, {
			method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams({
				grant_type: 'authorization_code', code, client_id: clientId, code_verifier: codeVerifier, redirect_uri: 'http://localhost:9999/callback',
			}).toString(),
		});
		const gwToken = (await tokRes.json() as {access_token: string}).access_token;

		const gwMcpCall = async (method: string, params: Record<string, unknown> = {}, id = 1) =>
			fetch(`${gwUrl}/mcp`, {
				method: 'POST', headers: {'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: `Bearer ${gwToken}`}, body: JSON.stringify({
					jsonrpc: '2.0', method, id, params,
				}),
			});

		await gwMcpCall('initialize', {protocolVersion: '2025-03-26', capabilities: {}, clientInfo: {name: 'test', version: '1.0.0'}});
		await fn(gwMcpCall);
	} finally {
		testStore.close();
		await new Promise<void>((resolve) => {
			gw.close(() => {
				resolve();
			});
		});
	}
};

// Helper: start an HTTP server on a random port
const listenOnRandomPort = async (server: HttpServer): Promise<void> => {
	await new Promise<void>((resolve) => {
		server.listen(0, '127.0.0.1', resolve);
	});
};

describe('upstream error handling', () => {
	test('returns isError when upstream returns an MCP-level error', async () => {
		const token = await getAccessToken();

		await mcpCall(token, 'initialize', {
			protocolVersion: '2025-03-26',
			capabilities: {},
			clientInfo: {name: 'test', version: '1.0.0'},
		});

		const res = await mcpCall(token, 'tools/call', {name: 'public-server__unknown_tool_xyz', arguments: {}}, 2);
		expect(res.status).toBe(200);
		const body = await res.json() as {result: {content: {text: string}[]; isError: boolean}};
		expect(body.result.isError).toBe(true);
	}, 30_000);

	test('returns isError when upstream returns non-MCP (HTML) response', async () => {
		const htmlServer = createServer((_req, res) => {
			res.writeHead(200, {'Content-Type': 'text/html'});
			res.end('<html><body>Oops, wrong server</body></html>');
		});
		await listenOnRandomPort(htmlServer);

		try {
			await withTestGateway(htmlServer, 'bad-server', {}, async (gwMcpCall) => {
				const res = await gwMcpCall('tools/call', {name: 'bad-server__anything', arguments: {}}, 2);
				expect(res.status).toBe(200);
				const body = await res.json() as {result: {content: {text: string}[]; isError: boolean}};
				expect(body.result.isError).toBe(true);
			});
		} finally {
			await new Promise<void>((resolve) => {
				htmlServer.close(() => {
					resolve();
				});
			});
		}
	}, 30_000);

	test('returns isError when upstream returns a 302 redirect', async () => {
		const redirectServer = createServer((_req, res) => {
			res.writeHead(302, {Location: 'http://example.com/login'});
			res.end();
		});
		await listenOnRandomPort(redirectServer);

		try {
			await withTestGateway(redirectServer, 'redirect-server', {}, async (gwMcpCall) => {
				const res = await gwMcpCall('tools/call', {name: 'redirect-server__anything', arguments: {}}, 2);
				expect(res.status).toBe(200);
				const body = await res.json() as {result: {content: {text: string}[]; isError: boolean}};
				expect(body.result.isError).toBe(true);
			});
		} finally {
			await new Promise<void>((resolve) => {
				redirectServer.close(() => {
					resolve();
				});
			});
		}
	}, 30_000);

	test('returns isError when upstream hangs (slowloris)', async () => {
		const hangServer = createServer(() => {
			// Intentionally do nothing — connection hangs
		});
		await listenOnRandomPort(hangServer);

		try {
			await withTestGateway(hangServer, 'hang-server', {discoveryTimeout: 1000}, async (gwMcpCall) => {
				const start = Date.now();
				const res = await gwMcpCall('tools/call', {name: 'hang-server__anything', arguments: {}}, 2);
				const elapsed = Date.now() - start;

				expect(res.status).toBe(200);
				const body = await res.json() as {result: {content: {text: string}[]; isError: boolean}};
				expect(body.result.isError).toBe(true);
				expect(elapsed).toBeLessThan(5000);
			});
		} finally {
			hangServer.closeAllConnections?.();
			await new Promise<void>((resolve) => {
				hangServer.close(() => {
					resolve();
				});
			});
		}
	}, 30_000);
});
