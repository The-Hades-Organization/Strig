// Run by web-core.mjs in a CommonJS process: the subpaths must load with require(), as a default NestJS project does.
const assert = require('node:assert/strict');
for (const [path, names] of [
  ['../express.js', ['authorize', 'createCan']],
  ['../fastify.js', ['authorize', 'createCan', 'plugin']],
  ['../nestjs.js', ['Can', 'ThemisGuard']],
]) {
  const mod = require(path);
  for (const name of names) assert.equal(typeof mod[name], 'function', `${path} ${name}`);
}
console.log('ok');
