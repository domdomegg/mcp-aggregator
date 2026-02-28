import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type {Transport} from '@modelcontextprotocol/sdk/shared/transport.js';
import type {OAuthClientInformationFull} from '@modelcontextprotocol/sdk/shared/auth.js';
import type {AuthorizationParams} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import {mcpAuthRouter, getOAuthProtectedResourceMetadataUrl} from '@modelcontextprotocol/sdk/server/auth/router.js';
import {requireBearerAuth} from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import express from 'express';
import type {GatewayOAuthProvider} from './oauth-provider.js';
import type {OidcClient} from './oidc-client.js';
import type {TokenStore} from './token-store.js';
import type {UpstreamManager} from './upstream-manager.js';
import type {GatewayConfig} from './types.js';
import {createGatewayServer} from './gateway-server.js';
import {renderSuccessPage, renderErrorPage} from './pages.js';

const getString = (value: unknown): string | undefined =>
	typeof value === 'string' ? value : undefined;

export const createApp = (
	config: GatewayConfig,
	provider: GatewayOAuthProvider,
	oidcClient: OidcClient,
	store: TokenStore,
	upstreamManager: UpstreamManager,
): express.Express => {
	const app = express();
	const getBaseUrl = () => config.issuerUrl ?? `http://localhost:${config.port ?? 3000}`;
	const issuerUrl = new URL(getBaseUrl());
	const mcpUrl = new URL('/mcp', issuerUrl);

	// Custom /authorize handler — accepts any client_id and redirect_uri without
	// requiring prior registration (same pattern as mcp-auth-wrapper).
	app.all('/authorize', (req, res) => {
		const params = req.method === 'POST' ? req.body as Record<string, unknown> : req.query;

		const clientId = getString(params.client_id);
		const redirectUri = getString(params.redirect_uri);
		const codeChallenge = getString(params.code_challenge);
		const codeChallengeMethod = getString(params.code_challenge_method);
		const scope = getString(params.scope);
		const state = getString(params.state);

		if (!clientId || !redirectUri || !codeChallenge) {
			res.status(400).json({error: 'invalid_request', error_description: 'Missing client_id, redirect_uri, or code_challenge'});
			return;
		}

		if (codeChallengeMethod && codeChallengeMethod !== 'S256') {
			res.status(400).json({error: 'invalid_request', error_description: 'code_challenge_method must be S256'});
			return;
		}

		const client = {client_id: clientId, redirect_uris: [redirectUri]} as OAuthClientInformationFull;
		const authParams: AuthorizationParams = {
			scopes: scope ? scope.split(' ') : [],
			redirectUri,
			codeChallenge,
		};
		if (state) {
			authParams.state = state;
		}

		void provider.authorize(client, authParams, res).catch((err: unknown) => {
			console.error('Authorize error:', err);
			if (!res.headersSent) {
				res.status(500).json({error: 'server_error'});
			}
		});
	});

	// OAuth routes (discovery, token, register, revoke).
	// Rate limiting is disabled: tokens are AES-256-GCM sealed blobs with fresh
	// random IVs and mandatory PKCE — brute forcing is cryptographically infeasible.
	const noRateLimit = {rateLimit: false as const};
	app.use(mcpAuthRouter({
		provider,
		issuerUrl,
		baseUrl: issuerUrl,
		resourceServerUrl: mcpUrl,
		tokenOptions: noRateLimit,
		authorizationOptions: noRateLimit,
		clientRegistrationOptions: noRateLimit,
		revocationOptions: noRateLimit,
	}));

	// OIDC callback from hass-oidc-provider
	app.get('/callback', async (req, res) => {
		try {
			const code = getString(req.query.code);
			const sealedState = getString(req.query.state);

			if (!code || !sealedState) {
				res.status(400).send('Missing code or state parameter');
				return;
			}

			const pending = provider.unsealState(sealedState);
			if (!pending) {
				res.status(400).send('Invalid or expired authorization session');
				return;
			}

			const callbackUrl = `${getBaseUrl()}/callback`;
			const {userId} = await oidcClient.exchangeCode(code, callbackUrl, pending.upstreamCodeVerifier);

			const {redirectUrl} = provider.completeAuthorization(pending, userId);
			res.redirect(redirectUrl);
		} catch (err) {
			console.error('Callback error:', err);
			res.status(500).send('Authentication failed');
		}
	});

	// Upstream auth: start OAuth flow with an upstream server
	app.get('/upstream-auth/start', async (req, res) => {
		const upstreamName = getString(req.query.upstream);
		const token = getString(req.query.token);

		if (!upstreamName || !token) {
			res.status(400).send('Missing upstream or token parameter');
			return;
		}

		try {
			const authInfo = await provider.verifyAccessToken(token);
			const userId = getString(authInfo.extra?.userId);
			if (!userId) {
				res.status(401).send('Missing user identity');
				return;
			}

			const authUrl = await upstreamManager.startUpstreamAuth(userId, upstreamName);
			res.redirect(authUrl);
		} catch (err) {
			console.error('Upstream auth start error:', err);
			res.status(500).send(renderErrorPage('Failed to start upstream authentication'));
		}
	});

	// Upstream auth: callback from upstream OAuth
	app.get('/upstream-auth/callback', async (req, res) => {
		const stateParam = getString(req.query.state);
		const code = getString(req.query.code);

		if (!stateParam || !code) {
			res.status(400).send(renderErrorPage('Missing state or code parameter'));
			return;
		}

		try {
			const {upstreamName} = await upstreamManager.handleUpstreamCallback(stateParam, code);
			res.send(renderSuccessPage(upstreamName));
		} catch (err) {
			console.error('Upstream auth callback error:', err);
			const message = err instanceof Error ? err.message : 'Unknown error';
			res.status(500).send(renderErrorPage(message));
		}
	});

	// Protected MCP endpoint
	const bearerAuth = requireBearerAuth({
		verifier: provider,
		resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpUrl),
	});

	app.all('/mcp', bearerAuth, async (req, res) => {
		const userId = getString(req.auth?.extra?.userId);
		if (!userId) {
			res.status(401).json({error: 'Missing user identity'});
			return;
		}

		const accessToken = req.auth!.token;

		// Stateless: fresh transport and server per request
		const transport = new StreamableHTTPServerTransport({
			enableJsonResponse: true,
		});

		const server = createGatewayServer(upstreamManager, store, userId, getBaseUrl(), accessToken);
		await server.connect(transport as unknown as Transport);

		await transport.handleRequest(req, res);
	});

	return app;
};
