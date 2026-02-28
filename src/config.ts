import fs from 'node:fs';
import {GatewayConfigSchema} from './types.js';
import type {GatewayConfig} from './types.js';

const DEFAULT_CONFIG_PATH = 'mcp-gateway.config.json';

export const loadConfig = (input?: string): GatewayConfig => {
	const raw = input ?? process.env.MCP_GATEWAY_CONFIG;

	let json: unknown;

	if (!raw) {
		if (fs.existsSync(DEFAULT_CONFIG_PATH)) {
			json = JSON.parse(fs.readFileSync(DEFAULT_CONFIG_PATH, 'utf8'));
		} else {
			throw new Error('No config found. Set MCP_GATEWAY_CONFIG or create mcp-gateway.config.json');
		}
	} else if (!raw.startsWith('{') && fs.existsSync(raw)) {
		// If it looks like a file path, read it
		json = JSON.parse(fs.readFileSync(raw, 'utf8'));
	} else {
		json = JSON.parse(raw);
	}

	const result = GatewayConfigSchema.safeParse(json);
	if (!result.success) {
		const issues = result.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
		throw new Error(`Invalid config:\n${issues}`);
	}

	return result.data;
};
