import Fastify from 'fastify';
import { authorize } from '../fastify.js';
import { runSuite } from './web-suite.mjs';

await runSuite('fastify', async (options) => {
  const app = Fastify();
  let ran = false;
  app.get('/doc/:id', { preHandler: authorize(options) }, async () => ((ran = true), { ok: true }));
  const base = await app.listen({ port: 0, host: '127.0.0.1' });
  return {
    async call(user, id) {
      ran = false;
      const res = await fetch(`${base}/doc/${id}`, { headers: user ? { 'x-user': user } : {} });
      return { status: res.status, body: await res.json(), handlerRan: ran };
    },
    close: () => app.close(),
  };
});
