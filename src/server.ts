import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type {Transport} from '@modelcontextprotocol/sdk/shared/transport.js';
import type {OAuthClientInformationFull} from '@modelcontextprotocol/sdk/shared/auth.js';
import type {AuthorizationParams} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import {mcpAuthRouter, getOAuthProtectedResourceMetadataUrl} from '@modelcontextprotocol/sdk/server/auth/router.js';
import {requireBearerAuth} from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import {InvalidTokenError} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import express from 'express';
import type {GatewayOAuthProvider} from './oauth-provider.js';
import type {OidcClient} from './oidc-client.js';
import type {TokenStore} from './token-store.js';
import type {UpstreamManager} from './upstream-manager.js';
import type {GatewayConfig} from './types.js';
import {createGatewayServer} from './gateway-server.js';
import {
	renderLandingPage, renderSuccessPage, renderErrorPage, renderDashboardPage, renderAuthCompletePage,
} from './pages.js';

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
			const dashboardToken = provider.createDashboardToken(userId);
			const dashboardUrl = `${getBaseUrl()}/dashboard?token=${dashboardToken}`;
			res.send(renderAuthCompletePage(redirectUrl, dashboardUrl));
		} catch (err) {
			console.error('Callback error:', err);
			res.status(500).send('Authentication failed');
		}
	});

	// Landing page
	app.get('/', (_req, res) => {
		const installUrl = `https://adamjones.me/install-mcp/?url=${encodeURIComponent(mcpUrl.href)}`;
		res.send(renderLandingPage(installUrl));
	});

	// Web login: /login → upstream IDP → /login/callback → /dashboard
	app.get('/login', (_req, res) => {
		const {codeVerifier, codeChallenge} = oidcClient.generateCodeVerifierAndChallenge();
		const state = provider.sealWebLogin(codeVerifier);
		const callbackUrl = `${getBaseUrl()}/login/callback`;

		oidcClient.buildAuthorizeUrl({redirectUri: callbackUrl, state, codeChallenge})
			.then((url) => {
				res.redirect(url);
			})
			.catch((err: unknown) => {
				console.error('Login error:', err);
				res.status(500).send(renderErrorPage('Failed to initiate login'));
			});
	});

	app.get('/login/callback', async (req, res) => {
		try {
			const code = getString(req.query.code);
			const state = getString(req.query.state);
			if (!code || !state) {
				res.status(400).send(renderErrorPage('Missing code or state parameter'));
				return;
			}

			const payload = provider.unsealWebLogin(state);
			if (!payload) {
				res.status(400).send(renderErrorPage('Invalid or expired login session'));
				return;
			}

			const callbackUrl = `${getBaseUrl()}/login/callback`;
			const {userId} = await oidcClient.exchangeCode(code, callbackUrl, payload.upstreamCodeVerifier);

			const token = provider.createDashboardToken(userId);
			res.redirect(`${getBaseUrl()}/dashboard?token=${encodeURIComponent(token)}`);
		} catch (err) {
			console.error('Login callback error:', err);
			res.status(500).send(renderErrorPage('Authentication failed'));
		}
	});

	// Dashboard: shows all upstreams with auth status and login links
	app.get('/dashboard', async (req, res) => {
		const token = getString(req.query.token);
		if (!token) {
			res.status(400).send(renderErrorPage('Missing token parameter'));
			return;
		}

		try {
			const authInfo = await provider.verifyAccessToken(token);
			const userId = getString(authInfo.extra?.userId);
			if (!userId) {
				res.status(401).send(renderErrorPage('Missing user identity'));
				return;
			}

			const upstreams = await Promise.all(config.upstreams.map(async (upstream) => {
				const status = await upstreamManager.getUpstreamStatus(upstream.name, userId);
				const upstreamAuthUrl = `${getBaseUrl()}/upstream-auth/start?upstream=${upstream.name}&token=${token}`;
				const authUrl = !status.connected ? upstreamAuthUrl : undefined;
				const disconnectUrl = status.connected && status.requiresOAuth
					? `${getBaseUrl()}/dashboard/disconnect?upstream=${upstream.name}&token=${token}`
					: undefined;
				const reconfigureUrl = status.connected && status.requiresOAuth ? upstreamAuthUrl : undefined;

				return {
					name: upstream.name,
					authenticated: status.connected,
					...(authUrl ? {authUrl} : {}),
					...(disconnectUrl ? {disconnectUrl} : {}),
					...(reconfigureUrl ? {reconfigureUrl} : {}),
				};
			}));

			res.send(renderDashboardPage(upstreams));
		} catch (err) {
			if (err instanceof InvalidTokenError) {
				res.redirect(`${getBaseUrl()}/login`);
				return;
			}
			console.error('Dashboard error:', err);
			res.status(500).send(renderErrorPage('Failed to load dashboard'));
		}
	});

	// Dashboard: disconnect an upstream
	app.get('/dashboard/disconnect', async (req, res) => {
		const upstreamName = getString(req.query.upstream);
		const token = getString(req.query.token);

		if (!upstreamName || !token) {
			res.status(400).send(renderErrorPage('Missing upstream or token parameter'));
			return;
		}

		try {
			const authInfo = await provider.verifyAccessToken(token);
			const userId = getString(authInfo.extra?.userId);
			if (!userId) {
				res.status(401).send(renderErrorPage('Missing user identity'));
				return;
			}

			store.deleteToken(userId, upstreamName);
			res.redirect(`${getBaseUrl()}/dashboard?token=${token}`);
		} catch (err) {
			if (err instanceof InvalidTokenError) {
				res.redirect(`${getBaseUrl()}/login`);
				return;
			}
			console.error('Dashboard disconnect error:', err);
			res.status(500).send(renderErrorPage('Failed to disconnect upstream'));
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

			const authUrl = await upstreamManager.startUpstreamAuth(userId, upstreamName, token);
			res.redirect(authUrl);
		} catch (err) {
			if (err instanceof InvalidTokenError) {
				res.redirect(`${getBaseUrl()}/login`);
				return;
			}
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
			const {upstreamName, gatewayToken} = await upstreamManager.handleUpstreamCallback(stateParam, code);
			if (gatewayToken) {
				res.redirect(`${getBaseUrl()}/dashboard?token=${gatewayToken}`);
			} else {
				res.send(renderSuccessPage(upstreamName));
			}
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
