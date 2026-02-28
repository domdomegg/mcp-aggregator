import {DatabaseSync} from 'node:sqlite';

export type StoredToken = {
	user_id: string;
	upstream_name: string;
	access_token: string;
	refresh_token: string | null;
	token_type: string;
	scope: string | null;
	expires_at: number | null;
};

export type StoredRegistration = {
	upstream_name: string;
	client_id: string;
	client_secret: string | null;
	registration_json: string;
};

export class TokenStore {
	private readonly db: DatabaseSync;

	constructor(storagePath?: string) {
		const isFile = storagePath && storagePath !== 'memory';
		this.db = new DatabaseSync(isFile ? storagePath : ':memory:');

		this.db.exec(`
			CREATE TABLE IF NOT EXISTS upstream_tokens (
				user_id TEXT NOT NULL,
				upstream_name TEXT NOT NULL,
				access_token TEXT NOT NULL,
				refresh_token TEXT,
				token_type TEXT NOT NULL DEFAULT 'bearer',
				scope TEXT,
				expires_at INTEGER,
				UNIQUE(user_id, upstream_name)
			)
		`);

		this.db.exec(`
			CREATE TABLE IF NOT EXISTS upstream_registrations (
				upstream_name TEXT PRIMARY KEY,
				client_id TEXT NOT NULL,
				client_secret TEXT,
				registration_json TEXT NOT NULL
			)
		`);
	}

	getToken(userId: string, upstreamName: string): StoredToken | undefined {
		return this.db.prepare('SELECT * FROM upstream_tokens WHERE user_id = ? AND upstream_name = ?').get(userId, upstreamName) as StoredToken | undefined;
	}

	upsertToken(userId: string, upstreamName: string, tokens: {
		access_token: string;
		refresh_token?: string | null;
		token_type?: string;
		scope?: string;
		expires_in?: number;
	}): void {
		this.db.prepare(`
			INSERT INTO upstream_tokens (user_id, upstream_name, access_token, refresh_token, token_type, scope, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(user_id, upstream_name) DO UPDATE SET
				access_token = excluded.access_token,
				refresh_token = COALESCE(excluded.refresh_token, upstream_tokens.refresh_token),
				token_type = excluded.token_type,
				scope = excluded.scope,
				expires_at = excluded.expires_at
		`).run(
			userId,
			upstreamName,
			tokens.access_token,
			tokens.refresh_token ?? null,
			tokens.token_type ?? 'bearer',
			tokens.scope ?? null,
			tokens.expires_in ? Math.floor(Date.now() / 1000) + tokens.expires_in : null,
		);
	}

	isTokenExpired(token: StoredToken): boolean {
		if (!token.expires_at) {
			return false;
		}

		return token.expires_at < Math.floor(Date.now() / 1000) - 60; // 60s buffer
	}

	getRegistration(upstreamName: string): StoredRegistration | undefined {
		return this.db.prepare('SELECT * FROM upstream_registrations WHERE upstream_name = ?').get(upstreamName) as StoredRegistration | undefined;
	}

	upsertRegistration(upstreamName: string, clientId: string, clientSecret: string | null, registrationJson: string): void {
		this.db.prepare(`
			INSERT INTO upstream_registrations (upstream_name, client_id, client_secret, registration_json)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(upstream_name) DO UPDATE SET
				client_id = excluded.client_id,
				client_secret = excluded.client_secret,
				registration_json = excluded.registration_json
		`).run(upstreamName, clientId, clientSecret, registrationJson);
	}

	deleteToken(userId: string, upstreamName: string): void {
		this.db.prepare('DELETE FROM upstream_tokens WHERE user_id = ? AND upstream_name = ?').run(userId, upstreamName);
	}

	hasToken(userId: string, upstreamName: string): boolean {
		const token = this.getToken(userId, upstreamName);
		return token !== undefined && !this.isTokenExpired(token);
	}

	close(): void {
		this.db.close();
	}
}
