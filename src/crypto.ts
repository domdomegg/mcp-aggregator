import {
	createCipheriv, createDecipheriv, createHash, randomBytes,
} from 'node:crypto';

/** Derive a 256-bit AES key from a secret string, or generate a random one. */
export const deriveKey = (secret?: string): Buffer =>
	secret
		? createHash('sha256').update(secret).digest()
		: randomBytes(32);

/** Encrypt + authenticate a JSON payload with AES-256-GCM. Returns a URL-safe base64 string. */
export const seal = <T>(payload: T, key: Buffer): string => {
	const iv = randomBytes(12);
	const cipher = createCipheriv('aes-256-gcm', key, iv);
	const plaintext = Buffer.from(JSON.stringify(payload));
	const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	const tag = cipher.getAuthTag();
	return Buffer.concat([iv, tag, encrypted]).toString('base64url');
};

/** Decrypt + verify a sealed payload. Returns undefined if tampered, expired, or wrong type. */
export const unseal = <T extends {type: string; expiresAt: number}>(sealed: string, key: Buffer, expectedType: T['type']): T | undefined => {
	try {
		const buf = Buffer.from(sealed, 'base64url');
		const iv = buf.subarray(0, 12);
		const tag = buf.subarray(12, 28);
		const encrypted = buf.subarray(28);
		const decipher = createDecipheriv('aes-256-gcm', key, iv);
		decipher.setAuthTag(tag);
		const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
		const payload = JSON.parse(decrypted.toString()) as T;
		if (payload.type !== expectedType || payload.expiresAt < Date.now()) {
			return undefined;
		}

		return payload;
	} catch {
		return undefined;
	}
};
