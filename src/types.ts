import {z} from 'zod';

export const AuthConfigSchema = z.object({
	issuer: z.url(),
	clientId: z.string().min(1),
	clientSecret: z.string().optional(),
	scopes: z.array(z.string()).optional(),
	userClaim: z.string().optional(),
});

export const UpstreamConfigSchema = z.object({
	/** Used as namespace prefix for tools (e.g. "gmail-mcp") */
	name: z.string().min(1),
	/** sHTTP endpoint URL (e.g. "https://gmail.mcp.home.adamjones.me/mcp") */
	url: z.url(),
	/** Pre-registered OAuth client_id. If set, Dynamic Client Registration is skipped. */
	clientId: z.string().min(1).optional(),
	/** Pre-registered OAuth client_secret (only used alongside clientId). */
	clientSecret: z.string().min(1).optional(),
});

export const GatewayConfigSchema = z.object({
	auth: AuthConfigSchema,
	upstreams: z.array(UpstreamConfigSchema).min(1),
	/** SQLite file path or "memory". Defaults to "memory". */
	storage: z.string().optional(),
	port: z.number().int().positive().optional(),
	host: z.string().optional(),
	/** External URL of this gateway (e.g. "https://gateway.mcp.home.adamjones.me") */
	issuerUrl: z.url().optional(),
	/** Secret for AES-256-GCM sealed tokens. If omitted, a random key is generated (tokens won't survive restarts). */
	secret: z.string().optional(),
	/** Timeout in ms for upstream discovery (connect + listTools). Defaults to 5000 (5s). */
	discoveryTimeout: z.number().int().positive().optional(),
	/** Timeout in ms for upstream tool calls. Defaults to 60000 (60s). */
	toolTimeout: z.number().int().positive().optional(),
});

export type AuthConfig = z.infer<typeof AuthConfigSchema>;
export type UpstreamConfig = z.infer<typeof UpstreamConfigSchema>;
export type GatewayConfig = z.infer<typeof GatewayConfigSchema>;
