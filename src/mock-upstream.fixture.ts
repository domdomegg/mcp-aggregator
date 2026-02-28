/**
 * Mock upstream MCP server for testing.
 * Speaks streamable HTTP with optional OAuth protection.
 * Exposes simple tools: echo, ping, get_server_name.
 */
import {createServer, type Server as HttpServer} from 'node:http';
import {randomUUID} from 'node:crypto';
import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type {Transport} from '@modelcontextprotocol/sdk/shared/transport.js';
import {
	ListToolsRequestSchema,
	CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import express from 'express';

export type MockUpstreamOptions = {
	name: string;
	/** If true, requires Bearer token and exposes OAuth discovery endpoints */
	requireAuth?: boolean;
	/** Accepted bearer tokens (if requireAuth) */
	validTokens?: Set<string>;
};

export type MockUpstream = {
	server: HttpServer;
	url: string;
	/** Issue an access token that will be accepted by this upstream */
	issueToken: () => string;
	/** Issue a refresh token that can be exchanged for a new access token */
	issueRefreshToken: () => string;
	close: () => Promise<void>;
};

// eslint-disable-next-line @typescript-eslint/no-deprecated -- Using low-level Server to match gateway pattern
const createMcpServer = (name: string): Server => {
	// eslint-disable-next-line @typescript-eslint/no-deprecated
	const server = new Server(
		{name, version: '1.0.0'},
		{capabilities: {tools: {}}},
	);

	server.setRequestHandler(ListToolsRequestSchema, async () => ({
		tools: [
			{
				name: 'echo',
				description: `[${name}] Echoes back the input`,
				inputSchema: {type: 'object' as const, properties: {message: {type: 'string'}}, required: ['message']},
			},
			{
				name: 'ping',
				description: `[${name}] Returns pong`,
				inputSchema: {type: 'object' as const, properties: {}},
			},
			{
				name: 'get_server_name',
				description: `[${name}] Returns this server's name`,
				inputSchema: {type: 'object' as const, properties: {}},
			},
		],
	}));

	server.setRequestHandler(CallToolRequestSchema, async (request) => {
		const {name: toolName, arguments: args} = request.params;
		const getArg = (key: string): string => {
			const val = args?.[key];
			return typeof val === 'string' ? val : '';
		};

		switch (toolName) {
			case 'echo':
				return {content: [{type: 'text' as const, text: getArg('message')}]};
			case 'ping':
				return {content: [{type: 'text' as const, text: 'pong'}]};
			case 'get_server_name':
				return {content: [{type: 'text' as const, text: name}]};
			default:
				return {content: [{type: 'text' as const, text: `Unknown tool: ${toolName}`}], isError: true};
		}
	});

	return server;
};

export const createMockUpstream = async (opts: MockUpstreamOptions): Promise<MockUpstream> => {
	const validTokens = opts.validTokens ?? new Set<string>();
	const validRefreshTokens = new Set<string>();
	const app = express();

	if (opts.requireAuth) {
		// OAuth discovery endpoints
		app.get('/.well-known/oauth-protected-resource', (_req, res) => {
			// Will be set after server starts and we know the URL
			res.json({
				resource: (app as unknown as {_baseUrl: string})._baseUrl,
				authorization_servers: [(app as unknown as {_baseUrl: string})._baseUrl],
			});
		});

		app.get('/.well-known/oauth-authorization-server', (_req, res) => {
			const base = (app as unknown as {_baseUrl: string})._baseUrl;
			res.json({
				issuer: base,
				authorization_endpoint: `${base}/authorize`,
				token_endpoint: `${base}/token`,
				registration_endpoint: `${base}/register`,
				response_types_supported: ['code'],
				grant_types_supported: ['authorization_code', 'refresh_token'],
				code_challenge_methods_supported: ['S256'],
			});
		});

		// Simple DCR
		app.post('/register', express.json(), (_req, res) => {
			res.status(201).json({
				client_id: randomUUID(),
				token_endpoint_auth_method: 'none',
			});
		});

		// Auto-approve authorize: issue code immediately
		const codes = new Map<string, {redirectUri: string; state: string | undefined}>();
		app.get('/authorize', (req, res) => {
			const redirectUri = req.query.redirect_uri as string;
			const state = req.query.state as string | undefined;
			const code = randomUUID();
			codes.set(code, {redirectUri, state});
			const url = new URL(redirectUri);
			url.searchParams.set('code', code);
			if (state) {
				url.searchParams.set('state', state);
			}

			res.redirect(url.toString());
		});

		// Token endpoint: handles authorization_code and refresh_token grants
		app.post('/token', express.urlencoded({extended: false}), (req, res) => {
			const grantType = req.body.grant_type as string;

			if (grantType === 'refresh_token') {
				const refreshToken = req.body.refresh_token as string;
				if (!validRefreshTokens.has(refreshToken)) {
					res.status(400).json({error: 'invalid_grant'});
					return;
				}

				validRefreshTokens.delete(refreshToken);
				const newToken = randomUUID();
				const newRefreshToken = randomUUID();
				validTokens.add(newToken);
				validRefreshTokens.add(newRefreshToken);
				res.json({
					access_token: newToken,
					refresh_token: newRefreshToken,
					token_type: 'bearer',
					expires_in: 3600,
				});
				return;
			}

			// authorization_code grant
			const code = req.body.code as string;
			if (!codes.has(code)) {
				res.status(400).json({error: 'invalid_grant'});
				return;
			}

			codes.delete(code);
			const token = randomUUID();
			const refreshToken = randomUUID();
			validTokens.add(token);
			validRefreshTokens.add(refreshToken);
			res.json({
				access_token: token,
				refresh_token: refreshToken,
				token_type: 'bearer',
				expires_in: 3600,
			});
		});
	}

	// MCP endpoint — enforces Bearer auth when requireAuth is set
	app.all('/mcp', async (req, res) => {
		if (opts.requireAuth) {
			const authHeader = req.headers.authorization ?? '';
			const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
			if (!validTokens.has(token)) {
				res.status(401).json({error: 'unauthorized'});
				return;
			}
		}

		const transport = new StreamableHTTPServerTransport({enableJsonResponse: true});
		const mcpServer = createMcpServer(opts.name);
		await mcpServer.connect(transport as unknown as Transport);
		await transport.handleRequest(req, res);
	});

	const httpServer = createServer(app);
	await new Promise<void>((resolve) => {
		httpServer.listen(0, '127.0.0.1', () => {
			resolve();
		});
	});

	const addr = httpServer.address();
	if (!addr || typeof addr === 'string') {
		throw new Error('Failed to start mock upstream');
	}

	const url = `http://127.0.0.1:${addr.port}`;
	(app as unknown as {_baseUrl: string})._baseUrl = url;

	return {
		server: httpServer,
		url,
		issueToken() {
			const token = randomUUID();
			validTokens.add(token);
			return token;
		},
		issueRefreshToken() {
			const refreshToken = randomUUID();
			validRefreshTokens.add(refreshToken);
			return refreshToken;
		},
		close: async () => new Promise<void>((resolve, reject) => {
			httpServer.close((err) => {
				if (err) {
					reject(err);
				} else {
					resolve();
				}
			});
		}),
	};
};
