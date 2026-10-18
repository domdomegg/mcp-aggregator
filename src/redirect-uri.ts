/**
 * We accept any redirect_uri without registration, and an attacker can start a flow with their
 * own redirect_uri and PKCE pair. So only hand codes to redirect URIs a remote attacker can't
 * receive; ask the user to confirm anything else.
 */

// A trailing * matches any suffix
export const DEFAULT_ALLOWED_REDIRECT_URIS = [
	'https://claude.ai/api/mcp/auth_callback',
	'https://claude.com/api/mcp/auth_callback',
	'https://chatgpt.com/connector_platform_oauth_redirect',
	'https://chatgpt.com/connector/oauth/*',
	'https://www.cursor.com/agents/mcp/oauth/callback',
];

const LOOPBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]']);

// eslint-disable-next-line no-script-url
const BLOCKED_SCHEMES = new Set(['javascript:', 'data:', 'file:', 'blob:', 'about:', 'vbscript:', 'filesystem:']);

export type RedirectUriVerdict = 'allowed' | 'needs_consent' | 'invalid';

export function checkRedirectUri(redirectUri: string, allowedRedirectUris: string[] = DEFAULT_ALLOWED_REDIRECT_URIS): RedirectUriVerdict {
	let url: URL;
	try {
		url = new URL(redirectUri);
	} catch {
		return 'invalid';
	}

	if (BLOCKED_SCHEMES.has(url.protocol) || url.hash) {
		return 'invalid';
	}

	// Native app schemes and loopback only reach the user's own machine
	if ((url.protocol !== 'http:' && url.protocol !== 'https:') || LOOPBACK_HOSTNAMES.has(url.hostname)) {
		return 'allowed';
	}

	const target = `${url.origin}${url.pathname}`;
	const isAllowed = allowedRedirectUris.some((allowed) => (allowed.endsWith('*') ? target.startsWith(allowed.slice(0, -1)) : target === allowed));
	return isAllowed ? 'allowed' : 'needs_consent';
}
