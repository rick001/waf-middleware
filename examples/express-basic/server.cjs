'use strict';

const express = require('express');
const { WafMiddleware } = require('http-waf-middleware');

const app = express();
app.use(express.json());
app.use(
  new WafMiddleware({
    sqlInjection: { enabled: true },
    queryDecode: { enabled: true, htmlEntities: true },
  }).use
);

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Express + WAF on http://127.0.0.1:${port}`);
});
