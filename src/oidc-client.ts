import {createHash, randomBytes} from 'node:crypto';
import {createRemoteJWKSet, jwtVerify} from 'jose';
import type {JWTVerifyGetKey} from 'jose';
import type {AuthConfig} from './types.js';

const parseCacheTtl = (headers: Headers, defaultMs: number): number => {
	const cacheControl = headers.get('cache-control');
	if (cacheControl) {
		const match = /max-age=(\d+)/.exec(cacheControl);
		if (match) {
			return Number(match[1]) * 1000;
		}
	}

	return defaultMs;
};

type OidcDiscovery = {
	authorization_endpoint: string;
	token_endpoint: string;
	jwks_uri: string;
	issuer: string;
};

const DEFAULT_DISCOVERY_TTL_MS = 3_600_000; // 1 hour

export class OidcClient {
	private discovery: OidcDiscovery | undefined;
	private discoveryExpiresAt = 0;
	private jwks: JWTVerifyGetKey | undefined;

	constructor(private readonly config: AuthConfig) {}

	async getDiscovery(): Promise<OidcDiscovery> {
		if (this.discovery && Date.now() < this.discoveryExpiresAt) {
			return this.discovery;
		}

		const url = `${this.config.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
		const res = await fetch(url);
		if (!res.ok) {
			throw new Error(`OIDC discovery failed: ${res.status} ${res.statusText}`);
		}

		this.discovery = await res.json() as OidcDiscovery;
		this.discoveryExpiresAt = Date.now() + parseCacheTtl(res.headers, DEFAULT_DISCOVERY_TTL_MS);
		return this.discovery;
	}

	async buildAuthorizeUrl(params: {
		redirectUri: string;
		state: string;
		codeChallenge: string;
	}): Promise<string> {
		const disc = await this.getDiscovery();
		const url = new URL(disc.authorization_endpoint);
		url.searchParams.set('client_id', this.config.clientId);
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('redirect_uri', params.redirectUri);
		url.searchParams.set('state', params.state);
		url.searchParams.set('scope', (this.config.scopes ?? ['openid']).join(' '));
		url.searchParams.set('code_challenge', params.codeChallenge);
		url.searchParams.set('code_challenge_method', 'S256');
		return url.toString();
	}

	generateCodeVerifierAndChallenge(): {codeVerifier: string; codeChallenge: string} {
		const codeVerifier = randomBytes(32).toString('base64url');
		const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
		return {codeVerifier, codeChallenge};
	}

	async exchangeCode(code: string, redirectUri: string, codeVerifier: string): Promise<{
		claims: Record<string, unknown>;
		userId: string;
	}> {
		const disc = await this.getDiscovery();
		const params = new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			redirect_uri: redirectUri,
			client_id: this.config.clientId,
			code_verifier: codeVerifier,
		});
		if (this.config.clientSecret) {
			params.set('client_secret', this.config.clientSecret);
		}

		const res = await fetch(disc.token_endpoint, {
			method: 'POST',
			headers: {'Content-Type': 'application/x-www-form-urlencoded'},
			body: params.toString(),
		});

		if (!res.ok) {
			const body = await res.text();
			throw new Error(`Upstream token exchange failed: ${res.status} ${body}`);
		}

		const tokens = await res.json() as {id_token?: string; access_token: string};

		if (tokens.id_token) {
			this.jwks ||= createRemoteJWKSet(new URL(disc.jwks_uri));

			const {payload} = await jwtVerify(tokens.id_token, this.jwks, {
				issuer: disc.issuer,
				audience: this.config.clientId,
			});

			const claim = this.config.userClaim ?? 'sub';
			const userId = payload[claim];
			if (typeof userId !== 'string') {
				throw new Error(`Upstream ID token missing claim "${claim}"`);
			}

			return {claims: payload as Record<string, unknown>, userId};
		}

		throw new Error('Upstream did not return an id_token');
	}
}
