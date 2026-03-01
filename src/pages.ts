export const renderSuccessPage = (upstreamName: string): string => `<!DOCTYPE html>
<html>
<head><title>Authentication successful</title></head>
<body>
<h1>Authenticated with ${escapeHtml(upstreamName)}</h1>
<p>You can close this tab and retry your request.</p>
</body>
</html>`;

export const renderErrorPage = (message: string): string => `<!DOCTYPE html>
<html>
<head><title>Authentication failed</title></head>
<body>
<h1>Authentication failed</h1>
<p>${escapeHtml(message)}</p>
</body>
</html>`;

export type DashboardUpstream = {
	name: string;
	authenticated: boolean;
	authUrl?: string;
	disconnectUrl?: string;
	reconfigureUrl?: string;
};

export const renderDashboardPage = (upstreams: DashboardUpstream[]): string => `<!DOCTYPE html>
<html>
<head>
<title>MCP Gateway</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; }
  h1 { font-size: 1.4em; margin-bottom: 4px; }
  p.subtitle { color: #666; margin-top: 0; }
  ul { list-style: none; padding: 0; }
  li { display: flex; align-items: center; justify-content: space-between; padding: 12px 16px; border: 1px solid #e0e0e0; border-radius: 8px; margin-bottom: 8px; }
  .name { font-weight: 500; }
  .actions { display: flex; gap: 6px; align-items: center; }
  .badge { font-size: 0.85em; padding: 4px 10px; border-radius: 12px; text-decoration: none; border: none; font: inherit; }
  .badge-ok { background: #e6f4ea; color: #1e7e34; }
  .badge-auth { background: #2563eb; color: #fff; cursor: pointer; }
  .badge-auth:hover { background: #1d4ed8; }
  .badge-reconfigure { background: #f3f4f6; color: #374151; cursor: pointer; }
  .badge-reconfigure:hover { background: #e5e7eb; }
  .badge-disconnect { background: none; color: #999; cursor: pointer; padding: 4px 8px; }
  .badge-disconnect:hover { color: #dc2626; }
</style>
</head>
<body>
<h1>MCP Gateway</h1>
<p class="subtitle">Upstream servers</p>
<ul>
${upstreams.map((u) => `  <li>
    <span class="name">${escapeHtml(u.name)}</span>
    <span class="actions">
    ${u.authenticated
		? `<span class="badge badge-ok">Connected</span>${u.reconfigureUrl ? `<a class="badge badge-reconfigure" href="${escapeHtml(u.reconfigureUrl)}">Reconfigure</a>` : ''}${u.disconnectUrl ? `<a class="badge badge-disconnect" href="${escapeHtml(u.disconnectUrl)}">Disconnect</a>` : ''}`
		: `<a class="badge badge-auth" href="${escapeHtml(u.authUrl ?? '#')}">Connect</a>`}
    </span>
  </li>`).join('\n')}
</ul>
</body>
</html>`;

export const renderAuthCompletePage = (clientRedirectUrl: string, dashboardUrl: string): string => `<!DOCTYPE html>
<html>
<head>
<title>MCP Gateway</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; text-align: center; }
  h1 { font-size: 1.4em; }
  p { color: #666; }
  .btn { display: inline-block; margin-top: 16px; padding: 10px 24px; background: #2563eb; color: #fff; border: none; border-radius: 8px; font-size: 1em; cursor: pointer; text-decoration: none; }
  .btn:hover { background: #1d4ed8; }
</style>
</head>
<body>
<h1>Welcome to MCP Gateway</h1>
<p>Connect your services to get started.</p>
<a id="go" class="btn" href="${escapeHtml(clientRedirectUrl)}">Connect services</a>
<script>
  document.getElementById('go').addEventListener('click', function(e) {
    e.preventDefault();
    window.open(${JSON.stringify(dashboardUrl)});
    window.location.href = ${JSON.stringify(clientRedirectUrl)};
  });
</script>
</body>
</html>`;

const escapeHtml = (s: string): string => s
	.replace(/&/g, '&amp;')
	.replace(/</g, '&lt;')
	.replace(/>/g, '&gt;')
	.replace(/"/g, '&quot;');
