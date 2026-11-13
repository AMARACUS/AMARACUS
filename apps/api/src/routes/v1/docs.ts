import { Router, Request, Response } from 'express';
import fs from 'fs';
import path from 'path';

const router = Router();

const openApiJsonPath = path.resolve(__dirname, '../../openapi/openapi.json');

// GET /api/v1/openapi.json - Canonical OpenAPI 3.1 specification
router.get('/openapi.json', (req: Request, res: Response) => {
  if (fs.existsSync(openApiJsonPath)) {
    const content = fs.readFileSync(openApiJsonPath, 'utf-8');
    res.setHeader('Content-Type', 'application/json');
    return res.send(content);
  }
  return res.status(404).json({
    error: {
      code: 'RESOURCE_NOT_FOUND',
      message: 'OpenAPI specification file not found.',
      requestId: (req as any).requestId,
    },
  });
});

// GET /api/v1/docs - Interactive API Documentation (Swagger UI)
router.get('/docs', (req: Request, res: Response) => {
  const swaggerHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AMARACUS Developer Platform API Documentation</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
  <link rel="icon" type="image/png" href="https://unpkg.com/swagger-ui-dist@5.11.0/favicon-32x32.png" sizes="32x32" />
  <style>
    html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin:0; background: #FAFDFB; font-family: sans-serif; }
    .topbar { display: none; }
    .swagger-ui .info .title { color: #008031; font-family: serif; }
    .swagger-ui .scheme-container { background: #FAFDFB; border-bottom: 1px solid #E9EDE7; }
    .swagger-ui .btn.authorize { background-color: #008031; border-color: #008031; color: #fff; }
    .swagger-ui .btn.authorize svg { fill: #fff; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js" charset="UTF-8"> </script>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-standalone-preset.js" charset="UTF-8"> </script>
  <script>
    window.onload = function() {
      window.ui = SwaggerUIBundle({
        url: "/api/v1/openapi.json",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html');
  return res.send(swaggerHtml);
});

export default router;
