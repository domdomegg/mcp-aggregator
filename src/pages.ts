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

const escapeHtml = (s: string): string => s
	.replace(/&/g, '&amp;')
	.replace(/</g, '&lt;')
	.replace(/>/g, '&gt;')
	.replace(/"/g, '&quot;');
