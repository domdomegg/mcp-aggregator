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
	expiresAt: number;
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

	/** Check if an upstream is known to require OAuth (from previous discovery or stored tokens). */
	upstreamRequiresOAuth(upstreamName: string, userId?: string): boolean {
		if (this.requiresOAuth.has(upstreamName)) {
			return true;
		}

		// If we have a stored token, the upstream must require OAuth
		if (userId && this.store.hasToken(userId, upstreamName)) {
			this.requiresOAuth.add(upstreamName);
			return true;
		}

		return false;
	}

	/** Probe whether an upstream requires OAuth by attempting RFC 9728 discovery. Caches result. */
	async probeUpstreamAuth(upstreamName: string): Promise<boolean> {
		if (this.requiresOAuth.has(upstreamName)) {
			return true;
		}

		const upstream = this.config.upstreams.find((u) => u.name === upstreamName);
		if (!upstream) {
			return false;
		}

		try {
			await this.discoverUpstreamOAuth(upstream);
			return true;
		} catch {
			return false;
		}
	}

	sealUpstreamState(state: UpstreamAuthState): string {
		return seal(state, this.key);
	}

	unsealUpstreamState(sealed: string): UpstreamAuthState | undefined {
		return unseal<UpstreamAuthState>(sealed, this.key, 'upstream_auth');
	}

	/** Build the URL a user should visit to authenticate with an upstream. */
	async startUpstreamAuth(userId: string, upstreamName: string): Promise<string> {
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
	async handleUpstreamCallback(stateParam: string, code: string): Promise<{upstreamName: string}> {
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
		return {upstreamName: state.upstreamName};
	}

	/** Get a connected MCP client for an upstream, injecting stored auth if needed. */
	async getClient(upstreamName: string, userId?: string): Promise<Client> {
		const upstream = this.config.upstreams.find((u) => u.name === upstreamName);
		if (!upstream) {
			throw new Error(`Unknown upstream: ${upstreamName}`);
		}

		const headers: Record<string, string> = {};

		// If we know this upstream requires OAuth (from cache, stored tokens, or previous discovery)
		if (userId && this.upstreamRequiresOAuth(upstreamName, userId)) {
			const token = this.store.getToken(userId, upstreamName);
			if (!token) {
				const authUrl = `${this.getBaseUrl()}/upstream-auth/start?upstream=${upstreamName}`;
				throw new UpstreamAuthRequiredError(upstreamName, authUrl);
			}

			if (this.store.isTokenExpired(token) && token.refresh_token) {
				await this.refreshUpstreamToken(upstream, userId, token.refresh_token);
				const refreshed = this.store.getToken(userId, upstreamName)!;
				headers.Authorization = `Bearer ${refreshed.access_token}`;
			} else if (this.store.isTokenExpired(token)) {
				const authUrl = `${this.getBaseUrl()}/upstream-auth/start?upstream=${upstreamName}`;
				throw new UpstreamAuthRequiredError(upstreamName, authUrl);
			} else {
				headers.Authorization = `Bearer ${token.access_token}`;
			}
		}

		const client = new Client({name: 'mcp-gateway', version: '1.0.0'});
		const transport = new StreamableHTTPClientTransport(new URL(upstream.url), {
			requestInit: {headers},
		});
		await withTimeout(
			client.connect(transport as Parameters<Client['connect']>[0]),
			this.discoveryTimeout,
			`connect to ${upstreamName}`,
		);
		return client;
	}

	/** List tools from an upstream. Returns empty array if upstream is down. */
	async listTools(upstreamName: string): Promise<Tool[]> {
		const upstream = this.config.upstreams.find((u) => u.name === upstreamName);
		if (!upstream) {
			return [];
		}

		try {
			const client = new Client({name: 'mcp-gateway', version: '1.0.0'});
			const transport = new StreamableHTTPClientTransport(new URL(upstream.url));
			await withTimeout(
				client.connect(transport as Parameters<Client['connect']>[0]),
				this.discoveryTimeout,
				`connect to ${upstreamName}`,
			);
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
		} catch {
			console.error(`Failed to list tools from ${upstreamName}`);
			return [];
		}
	}

	/** Call a tool on an upstream with user auth. Detects OAuth requirements automatically. */
	async callTool(
		upstreamName: string,
		toolName: string,
		args: Record<string, unknown>,
		userId: string,
	): Promise<CallToolResult> {
		try {
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
		} catch (err) {
			// If we already know it needs OAuth, re-throw as-is
			if (err instanceof UpstreamAuthRequiredError) {
				throw err;
			}

			// If the error looks like a 401/auth failure and we haven't tried OAuth yet,
			// probe for OAuth metadata and mark this upstream as requiring auth
			if (!this.requiresOAuth.has(upstreamName) && this.looksLikeAuthError(err)) {
				const upstream = this.config.upstreams.find((u) => u.name === upstreamName);
				if (upstream) {
					try {
						await this.discoverUpstreamOAuth(upstream);
						// Discovery succeeded — this upstream requires OAuth
						this.requiresOAuth.add(upstreamName);
						const authUrl = `${this.getBaseUrl()}/upstream-auth/start?upstream=${upstreamName}`;
						throw new UpstreamAuthRequiredError(upstreamName, authUrl);
					} catch (discoverErr) {
						if (discoverErr instanceof UpstreamAuthRequiredError) {
							throw discoverErr;
						}

						// OAuth discovery failed — re-throw original error
					}
				}
			}

			throw err;
		}
	}

	/** Check if an error looks like an authentication failure. */
	private looksLikeAuthError(err: unknown): boolean {
		if (!(err instanceof Error)) {
			return false;
		}

		const message = err.message.toLowerCase();
		return message.includes('401') || message.includes('unauthorized');
	}

	private getBaseUrl(): string {
		return this.config.issuerUrl ?? `http://localhost:${this.config.port ?? 3000}`;
	}

	/** Discover upstream OAuth metadata (RFC 9728 + RFC 8414). Cached. */
	private async discoverUpstreamOAuth(upstream: UpstreamConfig): Promise<UpstreamOAuthMeta> {
		const cached = this.oauthMetaCache.get(upstream.name);
		if (cached && Date.now() < cached.expiresAt) {
			return cached.meta;
		}

		const serverUrl = new URL(upstream.url);
		const baseUrl = `${serverUrl.protocol}//${serverUrl.host}`;

		// RFC 9728: discover protected resource metadata
		const prmRes = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`, {
			signal: AbortSignal.timeout(this.discoveryTimeout),
		});
		if (!prmRes.ok) {
			throw new Error(`Failed to discover OAuth metadata for ${upstream.name}: ${prmRes.status}`);
		}

		const prm = await prmRes.json() as {authorization_servers?: string[]};
		const authServerUrl = prm.authorization_servers?.[0];
		if (!authServerUrl) {
			throw new Error(`No authorization server found for ${upstream.name}`);
		}

		// RFC 8414: discover authorization server metadata
		const asUrl = new URL(authServerUrl);
		const asMetaRes = await fetch(`${asUrl.origin}/.well-known/oauth-authorization-server`, {
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

	/** Register gateway as OAuth client with upstream (DCR). Cached in SQLite. */
	private async ensureRegistration(upstream: UpstreamConfig): Promise<{clientId: string; clientSecret: string | null}> {
		const existing = this.store.getRegistration(upstream.name);
		if (existing) {
			return {clientId: existing.client_id, clientSecret: existing.client_secret};
		}

		const meta = await this.discoverUpstreamOAuth(upstream);
		if (!meta.registrationEndpoint) {
			throw new Error(`Upstream ${upstream.name} does not support dynamic client registration`);
		}

		const callbackUrl = `${this.getBaseUrl()}/upstream-auth/callback`;
		const res = await fetch(meta.registrationEndpoint, {
			method: 'POST',
			headers: {'Content-Type': 'application/json'},
			body: JSON.stringify({
				redirect_uris: [callbackUrl],
				client_name: 'mcp-gateway',
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
