// Builds one npm package per platform from js/native/strig.<platform>.node and pins them as optionalDependencies
// of the main package. Usage: node scripts/package-platforms.mjs [outDir]   (default: js/platforms)
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const scope = '@the-hades-organization';
const platforms = JSON.parse(readFileSync(join(root, 'scripts/platforms.json'), 'utf8'));
const mainPath = join(root, 'js/package.json');
const main = JSON.parse(readFileSync(mainPath, 'utf8'));
const out = process.argv[2] ?? join(root, 'js/platforms');

rmSync(out, { recursive: true, force: true });
for (const p of platforms) {
  const binary = join(root, `js/native/strig.${p.platform}.node`);
  if (!existsSync(binary)) throw new Error(`missing ${binary}`);
  const dir = join(out, p.package);
  mkdirSync(dir, { recursive: true });
  copyFileSync(binary, join(dir, 'strig.node'));
  const manifest = {
    name: `${scope}/${p.package}`,
    version: main.version,
    description: `Strig native module (N-API) for ${p.platform}${p.libc ? ` (${p.libc})` : ''}.`,
    license: main.license,
    repository: main.repository,
    main: 'strig.node',
    files: ['strig.node'],
    os: [p.os],
    cpu: [p.cpu],
    ...(p.libc && { libc: [p.libc] }),
    engines: main.engines,
  };
  writeFileSync(join(dir, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(
    join(dir, 'README.md'),
    `# ${scope}/${p.package}\n\nNative module of [${scope}/strig](https://www.npmjs.com/package/${scope}/strig) for ${p.platform}. Install the main package instead; this one is pulled in as an optional dependency.\n`,
  );
}

main.optionalDependencies = Object.fromEntries(platforms.map((p) => [`${scope}/${p.package}`, main.version]));
writeFileSync(mainPath, `${JSON.stringify(main, null, 2)}\n`);
console.log(`${platforms.length} platform packages in ${out}`);
