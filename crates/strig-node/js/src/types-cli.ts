#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { generateTypes, type CatalogInput } from './types-gen.js';

const USAGE = 'usage: strig-types <catalog.json> [-o <output.ts>]';
const args = process.argv.slice(2);
const out = args.indexOf('-o');
const output = out >= 0 ? args.splice(out, 2)[1] : undefined;
const input = args[0];
if (!input || args.length !== 1 || (out >= 0 && !output)) {
  console.error(USAGE);
  process.exit(2);
}
try {
  const source = generateTypes(JSON.parse(readFileSync(input, 'utf8')) as CatalogInput);
  if (output) writeFileSync(output, source);
  else process.stdout.write(source);
} catch (error) {
  console.error(`strig-types: ${error instanceof Error ? error.message : error}`);
  process.exit(1);
}
