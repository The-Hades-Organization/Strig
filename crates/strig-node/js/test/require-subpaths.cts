// Run by web-core.js in a CommonJS process: the subpaths must load with require(), as a default NestJS project does.
import assert = require('node:assert/strict');
const targets: [string, string[]][] = [
  ['../dist/express.js', ['authorize', 'createCan']],
  ['../dist/fastify.js', ['authorize', 'createCan', 'plugin']],
  ['../dist/nestjs.js', ['Can', 'StrigGuard']],
];
for (const [path, names] of targets) {
  const mod = require(path);
  for (const name of names) assert.equal(typeof mod[name], 'function', `${path} ${name}`);
}
console.log('ok');
