import express from 'express';
import { authorize } from '../express.js';
import { runSuite } from './web-suite.mjs';

await runSuite('express', async (options) => {
  const app = express();
  let ran = false;
  app.get('/doc/:id', authorize(options), (req, res) => ((ran = true), res.json({ ok: true })));
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    async call(user, id) {
      ran = false;
      const res = await fetch(`${base}/doc/${id}`, { headers: user ? { 'x-user': user } : {} });
      return { status: res.status, body: await res.json(), handlerRan: ran };
    },
    close: () => new Promise((resolve) => (server.closeAllConnections(), server.close(resolve))),
  };
});
