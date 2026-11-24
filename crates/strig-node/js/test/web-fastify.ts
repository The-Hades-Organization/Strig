import Fastify from 'fastify';
import { authorize } from '../dist/fastify.js';
import type { AuthorizerOptions } from '../dist/fastify.js';
import { runSuite } from './web-suite.js';

await runSuite('fastify', async (options) => {
  const app = Fastify();
  let ran = false;
  app.get('/doc/:id', { preHandler: authorize(options as AuthorizerOptions) }, async () => ((ran = true), { ok: true }));
  const base = await app.listen({ port: 0, host: '127.0.0.1' });
  return {
    async call(user: string | undefined, id: string) {
      ran = false;
      const res = await fetch(`${base}/doc/${id}`, { headers: user ? { 'x-user': user } : {} });
      return { status: res.status, body: await res.json(), handlerRan: ran };
    },
    close: () => app.close(),
  };
});
