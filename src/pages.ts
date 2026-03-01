// eslint-disable-next-line @typescript-eslint/no-require-imports -- CJS module, can't use import.meta
const pkg = require('../package.json') as {version: string; repository?: {url?: string}};
const {version} = pkg;
const repoUrl = pkg.repository?.url?.replace(/\.git$/, '').replace(/^git\+/, '') ?? 'https://github.com/domdomegg/mcp-aggregator';

const VARS_LIGHT = `--bg: #fafafa; --fg: #111; --muted: #888; --subtle: #666; --border: #eaeaea;
      --link: #666; --link-line: #ccc; --link-hover: #111;
      --dot-ok: #22c55e; --dot-off: #ccc;
      --btn-bg: #111; --btn-fg: #fafafa; --btn-hover: #333;
      --error: #b91c1c;
      --footer: #aaa; --footer-hover: #888;`;

const VARS_DARK = `--bg: #161616; --fg: #e5e5e5; --muted: #777; --subtle: #999; --border: #2a2a2a;
      --link: #999; --link-line: #555; --link-hover: #e5e5e5;
      --dot-ok: #4ade80; --dot-off: #555;
      --btn-bg: #e5e5e5; --btn-fg: #161616; --btn-hover: #ccc;
      --error: #f87171;
      --footer: #555; --footer-hover: #777;`;

const BASE = `* { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', 'Consolas', monospace; padding: 48px 24px; max-width: 520px; margin: 0 auto; background: var(--bg); color: var(--fg); }
  h1 { font-size: 14px; text-transform: uppercase; letter-spacing: 2px; font-weight: 700; color: var(--muted); }`;

const FOOTER = `footer { margin-top: 32px; font-size: 10px; color: var(--footer); }
  footer a { color: var(--footer); text-decoration: none; }
  footer a:hover { color: var(--footer-hover); border-bottom: 1px solid var(--footer-hover); }`;

const footerHtml = `<footer><a href="${escapeHtml(repoUrl)}">mcp-aggregator</a> v${escapeHtml(version)}</footer>`;

const pageHead = (title: string, extraCss: string) => `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="generator" content="mcp-aggregator">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  @media (prefers-color-scheme: light) { :root { ${VARS_LIGHT} } }
  @media (prefers-color-scheme: dark) { :root { ${VARS_DARK} } }
  ${BASE}
  ${extraCss}
  ${FOOTER}
</style>
</head>`;

const CENTER_CSS = `h1 { margin-bottom: 0; }
  .center { text-align: center; margin-top: 80px; }
  .msg { font-size: 13px; line-height: 1.6; margin-top: 12px; color: var(--subtle); }`;

const BTN_CSS = `.btn { display: inline-block; margin-top: 20px; font: inherit; font-size: 12px; font-weight: 600; padding: 8px 20px; border-radius: 4px; border: none; cursor: pointer; text-decoration: none; background: var(--btn-bg); color: var(--btn-fg); }
  .btn:hover { background: var(--btn-hover); }`;

export const renderSuccessPage = (upstreamName: string): string => `${pageHead('Authentication successful', CENTER_CSS)}
<body>
<div class="center">
<h1>MCP Aggregator</h1>
<p class="msg">Authenticated with <strong>${escapeHtml(upstreamName)}</strong></p>
<p class="msg">You can close this tab and retry your request.</p>
${footerHtml}
</div>
</body>
</html>`;

export const renderErrorPage = (message: string): string => `${pageHead('Authentication failed', `${CENTER_CSS}
  .msg-err { color: var(--error); }`)}
<body>
<div class="center">
<h1>MCP Aggregator</h1>
<p class="msg msg-err">${escapeHtml(message)}</p>
${footerHtml}
</div>
</body>
</html>`;

export type DashboardUpstream = {
	name: string;
	authenticated: boolean;
	authUrl?: string;
	disconnectUrl?: string;
	reconfigureUrl?: string;
};

const DASHBOARD_CSS = `h1 { margin-bottom: 32px; }
  .server { display: flex; align-items: center; justify-content: space-between; padding: 14px 0; border-bottom: 1px solid var(--border); }
  .server:first-of-type { border-top: 1px solid var(--border); }
  .left { display: flex; align-items: center; gap: 10px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; }
  .dot-ok { background: var(--dot-ok); }
  .dot-off { background: var(--dot-off); }
  .server-name { font-size: 14px; font-weight: 500; }
  .actions { display: flex; gap: 10px; align-items: center; }
  .actions a { font-size: 12px; color: var(--link); text-decoration: none; border-bottom: 1px solid var(--link-line); padding-bottom: 1px; }
  .actions a:hover { color: var(--link-hover); border-bottom-color: var(--link-hover); }
  .actions .btn { font: inherit; font-size: 12px; font-weight: 600; margin: -3px 0; padding: 3px 12px 4px; border-radius: 3px; border: none; border-bottom: none; cursor: pointer; text-decoration: none; background: var(--btn-bg); color: var(--btn-fg); }
  .actions .btn:hover { background: var(--btn-hover); color: var(--btn-fg); border-bottom: none; }`;

const upstreamRow = (u: DashboardUpstream): string => {
	const dot = u.authenticated ? 'dot-ok' : 'dot-off';
	const actions = u.authenticated
		? [
			u.reconfigureUrl ? `<a href="${escapeHtml(u.reconfigureUrl)}">reconfigure</a>` : '',
			u.disconnectUrl ? `<a href="${escapeHtml(u.disconnectUrl)}">disconnect</a>` : '',
		].filter(Boolean).join('\n    ')
		: `<a class="btn" href="${escapeHtml(u.authUrl ?? '#')}">connect</a>`;

	return `<div class="server">
  <div class="left">
    <span class="dot ${dot}"></span>
    <span class="server-name">${escapeHtml(u.name)}</span>
  </div>
  <span class="actions">
    ${actions}
  </span>
</div>`;
};

export const renderDashboardPage = (upstreams: DashboardUpstream[]): string => `${pageHead('MCP Aggregator', DASHBOARD_CSS)}
<body>
<h1>MCP Aggregator</h1>
${upstreams.map((u) => upstreamRow(u)).join('\n')}
${footerHtml}
</body>
</html>`;

export const renderAuthCompletePage = (clientRedirectUrl: string, dashboardUrl: string): string => `${pageHead('MCP Aggregator', `${CENTER_CSS}
  ${BTN_CSS}`)}
<body>
<div class="center">
<h1>MCP Aggregator</h1>
<p class="msg">Connect your services to get started.</p>
<a id="go" class="btn" href="${escapeHtml(clientRedirectUrl)}">connect services</a>
${footerHtml}
</div>
<script>
  document.getElementById('go').addEventListener('click', function(e) {
    e.preventDefault();
    window.open(${JSON.stringify(dashboardUrl)});
    window.location.href = ${JSON.stringify(clientRedirectUrl)};
  });
</script>
</body>
</html>`;

function escapeHtml(s: string): string {
	return s
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}
