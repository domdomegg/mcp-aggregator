import {randomUUID} from 'node:crypto';
import type {Response} from 'express';
import type {OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens} from '@modelcontextprotocol/sdk/shared/auth.js';
import type {AuthorizationParams, OAuthServerProvider} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type {OAuthRegisteredClientsStore} from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type {AuthInfo} from '@modelcontextprotocol/sdk/server/auth/types.js';
import {InvalidTokenError} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import {deriveKey, seal, unseal} from './crypto.js';
import type {OidcClient} from './oidc-client.js';
import type {GatewayConfig} from './types.js';

const ACCESS_TOKEN_TTL_MS = 3_600_000; // 1 hour
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 3_600_000; // 30 days
const AUTH_CODE_TTL_MS = 300_000; // 5 minutes
const PENDING_AUTH_TTL_MS = 600_000; // 10 minutes

/** Data encoded into the upstream state parameter. */
type PendingAuthPayload = {
	type: 'pending';
	upstreamCodeVerifier: string;
	clientId: string;
	redirectUri: string;
	codeChallenge: string;
	state?: string;
	scopes: string[];
	expiresAt: number;
	userId?: string;
};

/** Data encoded into the authorization code. */
type AuthCodePayload = {
	type: 'auth_code';
	clientId: string;
	userId: string;
	codeChallenge: string;
	redirectUri: string;
	scopes: string[];
	expiresAt: number;
};

/** Data encoded into access and refresh tokens. */
type TokenPayload = {
	type: 'access' | 'refresh';
	clientId: string;
	userId: string;
	scopes: string[];
	expiresAt: number;
};

export class GatewayOAuthProvider implements OAuthServerProvider {
	readonly clientsStore: OAuthRegisteredClientsStore;
	private readonly key: Buffer;

	constructor(
		private readonly oidcClient: OidcClient,
		private readonly config: GatewayConfig,
	) {
		this.key = deriveKey(config.secret);

		this.clientsStore = {
			getClient: (clientId: string) => ({
				client_id: clientId,
				redirect_uris: [],
				token_endpoint_auth_method: 'none' as const,
			}) as OAuthClientInformationFull,
			registerClient: (metadata: OAuthClientInformationFull) => ({
				...metadata,
				client_id: metadata.client_id || randomUUID(),
				client_id_issued_at: Math.floor(Date.now() / 1000),
			}),
		};
	}

	async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
		const {codeVerifier, codeChallenge} = this.oidcClient.generateCodeVerifierAndChallenge();

		const payload: PendingAuthPayload = {
			type: 'pending',
			upstreamCodeVerifier: codeVerifier,
			clientId: client.client_id,
			redirectUri: params.redirectUri,
			codeChallenge: params.codeChallenge,
			scopes: params.scopes ?? [],
			expiresAt: Date.now() + PENDING_AUTH_TTL_MS,
		};
		if (params.state) {
			payload.state = params.state;
		}

		const sealedState = seal(payload, this.key);
		const issuerUrl = this.config.issuerUrl ?? `http://localhost:${this.config.port ?? 3000}`;
		const callbackUrl = `${issuerUrl}/callback`;

		const url = await this.oidcClient.buildAuthorizeUrl({
			redirectUri: callbackUrl,
			state: sealedState,
			codeChallenge,
		});

		res.redirect(url);
	}

	unsealState(sealedState: string): PendingAuthPayload | undefined {
		return unseal<PendingAuthPayload>(sealedState, this.key, 'pending');
	}

	sealState(payload: PendingAuthPayload): string {
		return seal(payload, this.key);
	}

	completeAuthorization(pending: PendingAuthPayload, userId: string): {redirectUrl: string} {
		const code = seal<AuthCodePayload>({
			type: 'auth_code',
			clientId: pending.clientId,
			userId,
			codeChallenge: pending.codeChallenge,
			redirectUri: pending.redirectUri,
			scopes: pending.scopes,
			expiresAt: Date.now() + AUTH_CODE_TTL_MS,
		}, this.key);

		const redirectUrl = new URL(pending.redirectUri);
		redirectUrl.searchParams.set('code', code);
		if (pending.state) {
			redirectUrl.searchParams.set('state', pending.state);
		}

		return {redirectUrl: redirectUrl.toString()};
	}

	async challengeForAuthorizationCode(_client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
		const ac = unseal<AuthCodePayload>(authorizationCode, this.key, 'auth_code');
		if (!ac) {
			throw new Error('Invalid authorization code');
		}

		return ac.codeChallenge;
	}

	async exchangeAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<OAuthTokens> {
		const ac = unseal<AuthCodePayload>(authorizationCode, this.key, 'auth_code');
		if (!ac) {
			throw new Error('Invalid authorization code');
		}

		if (ac.clientId !== client.client_id) {
			throw new Error('Authorization code was not issued to this client');
		}

		const accessToken = seal<TokenPayload>({
			type: 'access',
			clientId: client.client_id,
			userId: ac.userId,
			scopes: ac.scopes,
			expiresAt: Date.now() + ACCESS_TOKEN_TTL_MS,
		}, this.key);

		const refreshToken = seal<TokenPayload>({
			type: 'refresh',
			clientId: client.client_id,
			userId: ac.userId,
			scopes: ac.scopes,
			expiresAt: Date.now() + REFRESH_TOKEN_TTL_MS,
		}, this.key);

		return {
			access_token: accessToken,
			token_type: 'bearer',
			expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
			refresh_token: refreshToken,
			scope: ac.scopes.join(' '),
		};
	}

	async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string): Promise<OAuthTokens> {
		const rt = unseal<TokenPayload>(refreshToken, this.key, 'refresh');
		if (!rt) {
			throw new Error('Invalid refresh token');
		}

		if (rt.clientId !== client.client_id) {
			throw new Error('Refresh token was not issued to this client');
		}

		const newAccessToken = seal<TokenPayload>({
			type: 'access',
			clientId: client.client_id,
			userId: rt.userId,
			scopes: rt.scopes,
			expiresAt: Date.now() + ACCESS_TOKEN_TTL_MS,
		}, this.key);

		const newRefreshToken = seal<TokenPayload>({
			type: 'refresh',
			clientId: client.client_id,
			userId: rt.userId,
			scopes: rt.scopes,
			expiresAt: Date.now() + REFRESH_TOKEN_TTL_MS,
		}, this.key);

		return {
			access_token: newAccessToken,
			token_type: 'bearer',
			expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
			refresh_token: newRefreshToken,
			scope: rt.scopes.join(' '),
		};
	}

	async verifyAccessToken(token: string): Promise<AuthInfo> {
		const td = unseal<TokenPayload>(token, this.key, 'access');
		if (!td) {
			throw new InvalidTokenError('Invalid or expired access token');
		}

		return {
			token,
			clientId: td.clientId,
			scopes: td.scopes,
			expiresAt: Math.floor(td.expiresAt / 1000),
			extra: {userId: td.userId},
		};
	}

	// eslint-disable-next-line @typescript-eslint/no-unused-vars -- required by OAuthServerProvider interface
	async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
		// Tokens are stateless sealed blobs — revocation is a no-op.
	}

	/** Create a short-lived access token for the dashboard (e.g. after OIDC login). */
	createDashboardToken(userId: string): string {
		return seal<TokenPayload>({
			type: 'access',
			clientId: 'dashboard',
			userId,
			scopes: [],
			expiresAt: Date.now() + ACCESS_TOKEN_TTL_MS,
		}, this.key);
	}
}
