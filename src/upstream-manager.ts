import {createHash, randomBytes} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {CallToolResultSchema} from '@modelcontextprotocol/sdk/types.js';
import type {Tool, CallToolResult} from '@modelcontextprotocol/sdk/types.js';
import {deriveKey, seal, unseal} from './crypto.js';
import type {TokenStore} from './token-store.js';
import type {UpstreamConfig, GatewayConfig} from './types.js';

const DEFAULT_DISCOVERY_TIMEOUT_MS = 5_000;
const DEFAULT_TOOL_TIMEOUT_MS = 60_000;

// eslint-disable-next-line @typescript-eslint/no-empty-function -- Intentional no-op for ignoring close errors
const noop = () => {};

/** Race a promise against a timeout. Rejects with a descriptive error on timeout. */
const withTimeout = async <T>(promise: Promise<T>, ms: number, label: string): Promise<T> => {
	let timer: ReturnType<typeof setTimeout>;
	const timeout = new Promise<never>((_resolve, reject) => {
		timer = setTimeout(() => {
			reject(new Error(`Upstream timeout after ${ms}ms: ${label}`));
		}, ms);
	});
	try {
		return await Promise.race([promise, timeout]);
	} finally {
		clearTimeout(timer!);
	}
};

export class UpstreamAuthRequiredError extends Error {
	constructor(
		public readonly upstreamName: string,
		public readonly authUrl: string,
	) {
		super(`Authentication required for ${upstreamName}`);
	}
}

type UpstreamOAuthMeta = {
	authorizationEndpoint: string;
	tokenEndpoint: string;
	registrationEndpoint?: string | undefined;
};

type UpstreamAuthState = {
	type: 'upstream_auth';
	userId: string;
	upstreamName: string;
	codeVerifier: string;
	redirectUri: string;
	gatewayToken?: string | undefined;
	expiresAt: number;
};

export type UpstreamStatus = {
	/** Whether this upstream requires OAuth (false = public, no auth needed). */
	requiresOAuth: boolean;
	/** Whether the user has a usable connection (valid token or refreshable token). */
	connected: boolean;
};

export class UpstreamManager {
	private readonly key: Buffer;
	private readonly oauthMetaCache = new Map<string, {meta: UpstreamOAuthMeta; expiresAt: number}>();
	/** Cache of which upstreams require OAuth. Once discovered, stays true. */
	private readonly requiresOAuth = new Set<string>();

	constructor(
		private readonly config: GatewayConfig,
		private readonly store: TokenStore,
	) {
		this.key = deriveKey(config.secret);
	}

	get upstreams(): UpstreamConfig[] {
		return this.config.upstreams;
	}

	private get discoveryTimeout(): number {
		return this.config.discoveryTimeout ?? DEFAULT_DISCOVERY_TIMEOUT_MS;
	}

	private get toolTimeout(): number {
		return this.config.toolTimeout ?? DEFAULT_TOOL_TIMEOUT_MS;
	}

	/** Single source of truth for upstream auth status. Checks (in order):
	 *  1. In-memory cache of known OAuth upstreams
	 *  2. Any stored token row in the DB (expired or not — proves OAuth is required)
	 *  3. HTTP probe via RFC 9728 / RFC 8414 discovery */
	async getUpstreamStatus(upstreamName: string, userId: string): Promise<UpstreamStatus> {
		const token = this.store.getToken(userId, upstreamName);

		// If we already know it requires OAuth (from cache or a stored token row)
		if (this.requiresOAuth.has(upstreamName) || token) {
			this.requiresOAuth.add(upstreamName);
			const connected = token !== undefined
				&& (!this.store.isTokenExpired(token) || token.refresh_token !== null);
			return {requiresOAuth: true, connected};
		}

		// Probe via HTTP discovery
		const upstream = this.config.upstreams.find((u) => u.name === upstreamName);
		if (!upstream) {
			return {requiresOAuth: false, connected: true};
		}

		try {
			await this.discoverUpstreamOAuth(upstream);
			// discoverUpstreamOAuth adds to requiresOAuth on success
			return {requiresOAuth: true, connected: false};
		} catch {
			return {requiresOAuth: false, connected: true};
		}
	}

	sealUpstreamState(state: UpstreamAuthState): string {
		return seal(state, this.key);
	}

	unsealUpstreamState(sealed: string): UpstreamAuthState | undefined {
		return unseal<UpstreamAuthState>(sealed, this.key, 'upstream_auth');
	}

	/** Build the URL a user should visit to authenticate with an upstream. */
	async startUpstreamAuth(userId: string, upstreamName: string, gatewayToken?: string): Promise<string> {
		const upstream = this.config.upstreams.find((u) => u.name === upstreamName);
		if (!upstream) {
			throw new Error(`Unknown upstream: ${upstreamName}`);
		}

		const meta = await this.discoverUpstreamOAuth(upstream);
		const {clientId} = await this.ensureRegistration(upstream);

		const codeVerifier = randomBytes(32).toString('base64url');
		const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
		const callbackUrl = `${this.getBaseUrl()}/upstream-auth/callback`;

		const state: UpstreamAuthState = {
			type: 'upstream_auth',
			userId,
			upstreamName,
			codeVerifier,
			redirectUri: callbackUrl,
			gatewayToken,
			expiresAt: Date.now() + 600_000, // 10 minutes
		};

		const sealedState = this.sealUpstreamState(state);

		const url = new URL(meta.authorizationEndpoint);
		url.searchParams.set('client_id', clientId);
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('redirect_uri', callbackUrl);
		url.searchParams.set('state', sealedState);
		url.searchParams.set('code_challenge', codeChallenge);
		url.searchParams.set('code_challenge_method', 'S256');

		this.requiresOAuth.add(upstreamName);
		return url.toString();
	}

	/** Handle callback from upstream OAuth. Exchange code for tokens and store. */
	async handleUpstreamCallback(stateParam: string, code: string): Promise<{upstreamName: string; gatewayToken?: string | undefined}> {
		const state = this.unsealUpstreamState(stateParam);
		if (!state) {
			throw new Error('Invalid or expired upstream auth state');
		}

		const upstream = this.config.upstreams.find((u) => u.name === state.upstreamName);
		if (!upstream) {
			throw new Error(`Unknown upstream: ${state.upstreamName}`);
		}

		const meta = await this.discoverUpstreamOAuth(upstream);
		const {clientId, clientSecret} = await this.ensureRegistration(upstream);

		const params = new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			redirect_uri: state.redirectUri,
			client_id: clientId,
			code_verifier: state.codeVerifier,
		});
		if (clientSecret) {
			params.set('client_secret', clientSecret);
		}

		const res = await fetch(meta.tokenEndpoint, {
			method: 'POST',
			headers: {'Content-Type': 'application/x-www-form-urlencoded'},
			body: params.toString(),
			signal: AbortSignal.timeout(this.discoveryTimeout),
		});

		if (!res.ok) {
			const body = await res.text();
			throw new Error(`Token exchange failed for ${state.upstreamName}: ${res.status} ${body}`);
		}

		const tokens = await res.json() as {
			access_token: string;
			refresh_token?: string;
			token_type?: string;
			scope?: string;
			expires_in?: number;
		};

		this.store.upsertToken(state.userId, state.upstreamName, tokens);
		return {upstreamName: state.upstreamName, gatewayToken: state.gatewayToken};
	}

	/** Get a connected MCP client for an upstream, injecting stored auth if needed.
	 *  Self-contained: resolves tokens, refreshes if expired, discovers OAuth on 401. */
	async getClient(upstreamName: string, userId?: string): Promise<Client> {
		const upstream = this.config.upstreams.find((u) => u.name === upstreamName);
		if (!upstream) {
			throw new Error(`Unknown upstream: ${upstreamName}`);
		}

		const accessToken = userId
			? await this.resolveAccessToken(upstream, userId)
			: undefined;

		try {
			return await this.connectClient(upstream, accessToken);
		} catch (err) {
			// If we connected without auth and got a 401, discover OAuth and report it
			if (!accessToken && userId && this.looksLikeAuthError(err)) {
				try {
					await this.discoverUpstreamOAuth(upstream);
				} catch {
					throw err;
				}

				throw new UpstreamAuthRequiredError(upstreamName, `${this.getBaseUrl()}/upstream-auth/start?upstream=${upstreamName}`);
			}

			throw err;
		}
	}

	/** List tools from an upstream. Returns empty array if upstream is down or auth is required. */
	async listTools(upstreamName: string, userId?: string): Promise<Tool[]> {
		try {
			const client = await this.getClient(upstreamName, userId);
			try {
				const result = await withTimeout(
					client.listTools(),
					this.discoveryTimeout,
					`list tools from ${upstreamName}`,
				);
				return result.tools;
			} finally {
				await client.close().catch(noop);
			}
		} catch (err) {
			if (err instanceof UpstreamAuthRequiredError) {
				return [];
			}

			if (!this.looksLikeAuthError(err)) {
				console.error(`Failed to list tools from ${upstreamName}:`, err);
			}

			return [];
		}
	}

	/** Call a tool on an upstream with user auth. */
	async callTool(
		upstreamName: string,
		toolName: string,
		args: Record<string, unknown>,
		userId: string,
	): Promise<CallToolResult> {
		const client = await this.getClient(upstreamName, userId);
		try {
			return await withTimeout(
				client.callTool({name: toolName, arguments: args}, CallToolResultSchema) as Promise<CallToolResult>,
				this.toolTimeout,
				`call ${upstreamName}/${toolName}`,
			);
		} finally {
			await client.close().catch(noop);
		}
	}

	/** Resolve a valid access token for an upstream, refreshing if needed.
	 *  Returns undefined if the upstream is not known to require auth. */
	private async resolveAccessToken(upstream: UpstreamConfig, userId: string): Promise<string | undefined> {
		const token = this.store.getToken(userId, upstream.name);

		// A stored token (even expired) proves this upstream requires OAuth
		if (this.requiresOAuth.has(upstream.name) || token) {
			this.requiresOAuth.add(upstream.name);
			const authUrl = `${this.getBaseUrl()}/upstream-auth/start?upstream=${upstream.name}`;

			if (!token) {
				throw new UpstreamAuthRequiredError(upstream.name, authUrl);
			}

			if (!this.store.isTokenExpired(token)) {
				return token.access_token;
			}

			if (token.refresh_token) {
				await this.refreshUpstreamToken(upstream, userId, token.refresh_token);
				return this.store.getToken(userId, upstream.name)!.access_token;
			}

			throw new UpstreamAuthRequiredError(upstream.name, authUrl);
		}

		// Not known to require OAuth — will connect without auth
		return undefined;
	}

	private async connectClient(upstream: UpstreamConfig, accessToken?: string): Promise<Client> {
		const headers: Record<string, string> = {};
		if (accessToken) {
			headers.Authorization = `Bearer ${accessToken}`;
		}

		const client = new Client({name: 'mcp-aggregator', version: '1.0.0'});
		const transport = new StreamableHTTPClientTransport(new URL(upstream.url), {
			requestInit: {headers},
		});
		await withTimeout(
			client.connect(transport as Parameters<Client['connect']>[0]),
			this.discoveryTimeout,
			`connect to ${upstream.name}`,
		);
		return client;
	}

	/** Check if an error looks like an authentication failure. */
	private looksLikeAuthError(err: unknown): boolean {
		if (!(err instanceof Error)) {
			return false;
		}

		// Check for numeric code property (e.g. StreamableHTTPError.code)
		if ('code' in err && (err as {code: unknown}).code === 401) {
			return true;
		}

		const message = err.message.toLowerCase();
		return message.includes('401')
			|| message.includes('unauthorized')
			|| message.includes('invalid_token')
			|| message.includes('missing authorization');
	}

	private getBaseUrl(): string {
		return this.config.issuerUrl ?? `http://localhost:${this.config.port ?? 3000}`;
	}

	/** Discover upstream OAuth metadata (RFC 9728 + RFC 8414). Cached.
	 *  Tries RFC 9728 protected resource metadata first, falls back to
	 *  RFC 8414 authorization server metadata on the upstream's origin. */
	private async discoverUpstreamOAuth(upstream: UpstreamConfig): Promise<UpstreamOAuthMeta> {
		const cached = this.oauthMetaCache.get(upstream.name);
		if (cached && Date.now() < cached.expiresAt) {
			return cached.meta;
		}

		const serverUrl = new URL(upstream.url);
		const baseUrl = `${serverUrl.protocol}//${serverUrl.host}`;

		let authServerOrigin: string | undefined;

		// RFC 9728: discover protected resource metadata
		// Per Section 3.1, when the resource identifier contains a path component,
		// insert /.well-known/oauth-protected-resource between the host and path.
		// e.g. https://example.com/mcp → https://example.com/.well-known/oauth-protected-resource/mcp
		const resourcePath = serverUrl.pathname === '/' ? '' : serverUrl.pathname;
		try {
			const prmRes = await fetch(`${baseUrl}/.well-known/oauth-protected-resource${resourcePath}`, {
				signal: AbortSignal.timeout(this.discoveryTimeout),
			});
			if (prmRes.ok) {
				const prm = await prmRes.json() as {authorization_servers?: string[]};
				const authServerUrl = prm.authorization_servers?.[0];
				if (authServerUrl) {
					authServerOrigin = new URL(authServerUrl).origin;
				}
			}
		} catch {
			// RFC 9728 discovery failed — will fall back to RFC 8414 on upstream origin
		}

		// Fall back to using the upstream's own origin as the authorization server
		authServerOrigin ??= baseUrl;

		// RFC 8414: discover authorization server metadata
		const asMetaRes = await fetch(`${authServerOrigin}/.well-known/oauth-authorization-server`, {
			signal: AbortSignal.timeout(this.discoveryTimeout),
		});
		if (!asMetaRes.ok) {
			throw new Error(`Failed to discover auth server metadata for ${upstream.name}: ${asMetaRes.status}`);
		}

		const asMeta = await asMetaRes.json() as {
			authorization_endpoint: string;
			token_endpoint: string;
			registration_endpoint?: string;
		};

		const meta: UpstreamOAuthMeta = {
			authorizationEndpoint: asMeta.authorization_endpoint,
			tokenEndpoint: asMeta.token_endpoint,
			registrationEndpoint: asMeta.registration_endpoint,
		};

		this.oauthMetaCache.set(upstream.name, {meta, expiresAt: Date.now() + 3_600_000});
		this.requiresOAuth.add(upstream.name);
		return meta;
	}

	/** Register gateway as OAuth client with upstream (DCR), or fall back to
	 *  IndieAuth-style client_id (gateway base URL) when DCR is unavailable.
	 *  If the upstream config specifies a clientId, use that directly and skip DCR.
	 *  Cached in SQLite (except for pre-configured clients, which always read from config). */
	private async ensureRegistration(upstream: UpstreamConfig): Promise<{clientId: string; clientSecret: string | null}> {
		if (upstream.clientId) {
			return {clientId: upstream.clientId, clientSecret: upstream.clientSecret ?? null};
		}

		const existing = this.store.getRegistration(upstream.name);
		if (existing) {
			return {clientId: existing.client_id, clientSecret: existing.client_secret};
		}

		const meta = await this.discoverUpstreamOAuth(upstream);

		// If no registration endpoint, use IndieAuth convention: client_id = base URL of redirect_uri
		if (!meta.registrationEndpoint) {
			const clientId = this.getBaseUrl();
			this.store.upsertRegistration(upstream.name, clientId, null, JSON.stringify({client_id: clientId}));
			return {clientId, clientSecret: null};
		}

		const callbackUrl = `${this.getBaseUrl()}/upstream-auth/callback`;
		const res = await fetch(meta.registrationEndpoint, {
			method: 'POST',
			headers: {'Content-Type': 'application/json'},
			body: JSON.stringify({
				redirect_uris: [callbackUrl],
				client_name: 'mcp-aggregator',
				token_endpoint_auth_method: 'none',
				grant_types: ['authorization_code', 'refresh_token'],
				response_types: ['code'],
			}),
			signal: AbortSignal.timeout(this.discoveryTimeout),
		});

		if (!res.ok) {
			const body = await res.text();
			throw new Error(`DCR failed for ${upstream.name}: ${res.status} ${body}`);
		}

		const reg = await res.json() as {client_id: string; client_secret?: string};
		this.store.upsertRegistration(
			upstream.name,
			reg.client_id,
			reg.client_secret ?? null,
			JSON.stringify(reg),
		);

		return {clientId: reg.client_id, clientSecret: reg.client_secret ?? null};
	}

	/** Refresh an expired upstream token. */
	private async refreshUpstreamToken(upstream: UpstreamConfig, userId: string, refreshToken: string): Promise<void> {
		const meta = await this.discoverUpstreamOAuth(upstream);
		const {clientId, clientSecret} = await this.ensureRegistration(upstream);

		const params = new URLSearchParams({
			grant_type: 'refresh_token',
			refresh_token: refreshToken,
			client_id: clientId,
		});
		if (clientSecret) {
			params.set('client_secret', clientSecret);
		}

		const res = await fetch(meta.tokenEndpoint, {
			method: 'POST',
			headers: {'Content-Type': 'application/x-www-form-urlencoded'},
			body: params.toString(),
			signal: AbortSignal.timeout(this.discoveryTimeout),
		});

		if (!res.ok) {
			throw new Error(`Token refresh failed for ${upstream.name}: ${res.status}`);
		}

		const tokens = await res.json() as {
			access_token: string;
			refresh_token?: string;
			token_type?: string;
			scope?: string;
			expires_in?: number;
		};

		this.store.upsertToken(userId, upstream.name, tokens);
	}
}
