import {describe, test, expect} from 'vitest';
import {checkRedirectUri} from './redirect-uri.js';

describe('checkRedirectUri', () => {
	test.each([
		'http://localhost:33418/callback',
		'http://127.0.0.1:8080/oauth/callback',
		'http://[::1]:9000/cb',
		'cursor://anysphere.cursor-retrieval/oauth/callback',
		'https://claude.ai/api/mcp/auth_callback',
		'https://claude.ai/api/mcp/auth_callback?foo=bar',
	])('allows %s by default', (uri) => {
		expect(checkRedirectUri(uri)).toBe('allowed');
	});

	test.each([
		'https://attacker.example/cb',
		'https://claude.ai.attacker.example/api/mcp/auth_callback',
		'https://claude.ai/api/mcp/other',
		'https://localhost.attacker.example/cb',
	])('requires consent for %s', (uri) => {
		expect(checkRedirectUri(uri)).toBe('needs_consent');
	});

	test.each([
		'',
		'not a url',
		// eslint-disable-next-line no-script-url
		'javascript:alert(1)',
		'data:text/html,hi',
		'file:///etc/passwd',
		'http://localhost:3000/cb#frag',
	])('rejects %s', (uri) => {
		expect(checkRedirectUri(uri)).toBe('invalid');
	});

	test('trusts more well-known hosted clients by default', () => {
		expect(checkRedirectUri('https://chatgpt.com/connector/oauth/abc123')).toBe('allowed');
		expect(checkRedirectUri('https://vscode.dev/redirect')).toBe('needs_consent');
		expect(checkRedirectUri('https://chatgpt.com/other')).toBe('needs_consent');
	});

	test('supports trailing wildcards', () => {
		expect(checkRedirectUri('https://a.example/cb/123', ['https://a.example/cb/*'])).toBe('allowed');
		expect(checkRedirectUri('https://a.example/other', ['https://a.example/cb/*'])).toBe('needs_consent');
	});

	test('allowedRedirectUris replaces the defaults', () => {
		expect(checkRedirectUri('https://other.example/cb', ['https://other.example/cb'])).toBe('allowed');
		expect(checkRedirectUri('https://claude.ai/api/mcp/auth_callback', ['https://other.example/cb'])).toBe('needs_consent');
		expect(checkRedirectUri('https://claude.ai/api/mcp/auth_callback', [])).toBe('needs_consent');
		expect(checkRedirectUri('http://localhost:1/cb', [])).toBe('allowed');
	});
});
