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
			const upstreamTools = await upstreamManager.listTools(upstream.name, userId);
			return {upstream, tools: upstreamTools};
		}));

		for (const result of results) {
			if (result.status === 'fulfilled') {
				for (const tool of result.value.tools) {
					tools.push({
						...tool,
						name: `${result.value.upstream.name}__${tool.name}`,
						description: `[${result.value.upstream.name}] ${tool.description ?? ''}`,
					});
				}
			} else {
				console.error('Failed to discover tools from upstream:', result.reason);
			}
		}

		// Gateway meta-tools
		const upstreamStatuses = await Promise.all(upstreamManager.upstreams.map(async (u) => ({
			name: u.name,
			status: await upstreamManager.getUpstreamStatus(u.name, userId),
		})));
		const unauthServers = upstreamStatuses
			.filter((u) => u.status.requiresOAuth && !u.status.connected)
			.map((u) => u.name);
		const authDesc = unauthServers.length > 0
			? `Show authentication status and authenticate upstream MCP servers. Pass the "server" argument to check a single server (equivalent to calling gateway__{server}__auth). Servers requiring authentication: ${unauthServers.join(', ')}`
			: 'Show authentication status for upstream MCP servers. Pass the "server" argument to check a single server. All servers are currently connected.';
		tools.push({
			name: 'gateway__auth',
			description: authDesc,
			inputSchema: {
				type: 'object' as const,
				properties: {
					server: {type: 'string', description: 'Optional: name of a specific upstream server to check or authenticate'},
				},
			},
			annotations: {
				title: 'Gateway Authentication',
				readOnlyHint: true,
				openWorldHint: true,
			},
		});

		// Per-server auth tools for unauthenticated upstreams.
		// We expose both gateway__auth (general, with optional server arg) and
		// gateway__{server}__auth (specific) so that tool-search implementations
		// can match on the server name in the tool name itself, not just in the
		// description or arguments. Both resolve to the same handleAuthTool() logic.
		for (const serverName of unauthServers) {
			tools.push({
				name: `gateway__${serverName}__auth`,
				description: `[${serverName}] Authenticate with ${serverName}. This server requires authentication before its tools become available. Equivalent to calling gateway__auth with server="${serverName}".`,
				inputSchema: {type: 'object' as const, properties: {}},
				annotations: {
					title: `Authenticate ${serverName}`,
					readOnlyHint: true,
					openWorldHint: true,
				},
			});
		}

		tools.push({
			name: 'gateway__unauth',
			description: 'Remove stored authentication for an upstream MCP server, so you can re-authenticate or disconnect it.',
			inputSchema: {
				type: 'object' as const,
				properties: {
					server: {type: 'string', description: 'The name of the upstream server to deauthenticate'},
				},
				required: ['server'],
			},
			annotations: {
				title: 'Disconnect Server',
				readOnlyHint: false,
				destructiveHint: true,
				idempotentHint: true,
				openWorldHint: false,
			},
		});

		return {tools};
	});

	const handleAuthTool = async (serverFilter?: string) => {
		if (serverFilter && !upstreamManager.upstreams.find((u) => u.name === serverFilter)) {
			return {
				content: [{type: 'text' as const, text: `Unknown upstream: ${serverFilter}`}],
				isError: true,
			};
		}

		const upstreamsToCheck = serverFilter
			? upstreamManager.upstreams.filter((u) => u.name === serverFilter)
			: upstreamManager.upstreams;

		const statuses = await Promise.all(upstreamsToCheck.map(async (upstream) => {
			const status = await upstreamManager.getUpstreamStatus(upstream.name, userId);
			const authUrl = !status.connected
				? `${baseUrl}/upstream-auth/start?upstream=${upstream.name}&token=${accessToken}`
				: undefined;

			return {
				name: upstream.name,
				authenticated: status.connected,
				...(authUrl ? {authUrl} : {}),
			};
		}));

		const dashboardUrl = `${baseUrl}/dashboard?token=${accessToken}`;
		return {
			content: [{type: 'text' as const, text: JSON.stringify({dashboardUrl, servers: statuses}, null, 2)}],
		};
	};

	server.setRequestHandler(CallToolRequestSchema, async (request) => {
		const {name, arguments: args} = request.params;

		if (name === 'gateway__auth') {
			const serverFilter = typeof args?.server === 'string' ? args.server : undefined;
			return handleAuthTool(serverFilter);
		}

		if (name === 'gateway__unauth') {
			const serverName = typeof args?.server === 'string' ? args.server : undefined;
			if (!serverName) {
				return {
					content: [{type: 'text' as const, text: 'Missing required argument: server'}],
					isError: true,
				};
			}

			const upstream = upstreamManager.upstreams.find((u) => u.name === serverName);
			if (!upstream) {
				return {
					content: [{type: 'text' as const, text: `Unknown upstream: ${serverName}`}],
					isError: true,
				};
			}

			store.deleteToken(userId, serverName);
			return {
				content: [{type: 'text' as const, text: `Successfully removed authentication for ${serverName}`}],
			};
		}

		// Per-server auth tools: gateway__{server}__auth
		const perServerAuthMatch = /^gateway__(.+)__auth$/.exec(name);
		if (perServerAuthMatch) {
			const serverFilter = perServerAuthMatch[1]!;
			// Delegate to the same logic as gateway__auth with a server filter
			return handleAuthTool(serverFilter);
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
