/* eslint-disable @typescript-eslint/no-deprecated -- Using low-level Server to proxy JSON Schema without Zod conversion */
import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {
	ListToolsRequestSchema,
	CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import {UpstreamAuthRequiredError} from './upstream-manager.js';
import type {UpstreamManager} from './upstream-manager.js';
import type {TokenStore} from './token-store.js';

export const createGatewayServer = (
	upstreamManager: UpstreamManager,
	store: TokenStore,
	userId: string,
	baseUrl: string,
	accessToken: string,
): Server => {
	const server = new Server(
		{name: 'mcp-gateway', version: '1.0.0'},
		{capabilities: {tools: {}}},
	);

	server.setRequestHandler(ListToolsRequestSchema, async () => {
		const tools = [];

		const results = await Promise.allSettled(upstreamManager.upstreams.map(async (upstream) => {
			const upstreamTools = await upstreamManager.listTools(upstream.name);
			return {upstream, tools: upstreamTools};
		}));

		for (const result of results) {
			if (result.status === 'fulfilled') {
				for (const tool of result.value.tools) {
					tools.push({
						name: `${result.value.upstream.name}__${tool.name}`,
						description: `[${result.value.upstream.name}] ${tool.description ?? ''}`,
						inputSchema: tool.inputSchema,
					});
				}
			} else {
				console.error('Failed to discover tools from upstream:', result.reason);
			}
		}

		// Gateway meta-tools
		tools.push({
			name: 'gateway__status',
			description: 'Show all upstream MCP servers and their authentication status. Returns auth URLs for servers that need authentication.',
			inputSchema: {type: 'object' as const, properties: {}},
		});
		tools.push({
			name: 'gateway__unauth',
			description: 'Remove stored authentication for an upstream MCP server, so you can re-authenticate or disconnect it.',
			inputSchema: {
				type: 'object' as const,
				properties: {
					upstream: {type: 'string', description: 'The name of the upstream server to deauthenticate'},
				},
				required: ['upstream'],
			},
		});

		return {tools};
	});

	server.setRequestHandler(CallToolRequestSchema, async (request) => {
		const {name, arguments: args} = request.params;

		if (name === 'gateway__status') {
			const statuses = await Promise.all(upstreamManager.upstreams.map(async (upstream) => {
				const requiresOAuth = upstreamManager.upstreamRequiresOAuth(upstream.name, userId)
					|| await upstreamManager.probeUpstreamAuth(upstream.name);
				const hasToken = requiresOAuth
					? store.hasToken(userId, upstream.name)
					: true;
				const authUrl = !hasToken
					? `${baseUrl}/upstream-auth/start?upstream=${upstream.name}&token=${accessToken}`
					: undefined;

				return {
					name: upstream.name,
					authenticated: hasToken,
					...(authUrl ? {authUrl} : {}),
				};
			}));

			return {
				content: [{type: 'text' as const, text: JSON.stringify(statuses, null, 2)}],
			};
		}

		if (name === 'gateway__unauth') {
			const upstreamName = typeof args?.upstream === 'string' ? args.upstream : undefined;
			if (!upstreamName) {
				return {
					content: [{type: 'text' as const, text: 'Missing required argument: upstream'}],
					isError: true,
				};
			}

			const upstream = upstreamManager.upstreams.find((u) => u.name === upstreamName);
			if (!upstream) {
				return {
					content: [{type: 'text' as const, text: `Unknown upstream: ${upstreamName}`}],
					isError: true,
				};
			}

			store.deleteToken(userId, upstreamName);
			return {
				content: [{type: 'text' as const, text: `Successfully removed authentication for ${upstreamName}`}],
			};
		}

		// Route to upstream: parse namespace prefix
		const separatorIndex = name.indexOf('__');
		if (separatorIndex === -1) {
			return {
				content: [{type: 'text' as const, text: `Unknown tool: ${name}`}],
				isError: true,
			};
		}

		const upstreamName = name.slice(0, separatorIndex);
		const originalName = name.slice(separatorIndex + 2);

		try {
			return await upstreamManager.callTool(upstreamName, originalName, args ?? {}, userId);
		} catch (err) {
			if (err instanceof UpstreamAuthRequiredError) {
				const authUrl = `${baseUrl}/upstream-auth/start?upstream=${err.upstreamName}&token=${accessToken}`;
				return {
					content: [{
						type: 'text' as const,
						text: `Authentication required for ${err.upstreamName}. Please visit: ${authUrl}`,
					}],
					isError: true,
				};
			}

			const message = err instanceof Error ? err.message : String(err);
			return {
				content: [{type: 'text' as const, text: `Error calling ${upstreamName}: ${message}`}],
				isError: true,
			};
		}
	});

	return server;
};
