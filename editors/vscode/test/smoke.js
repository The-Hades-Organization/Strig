'use strict';

// A cheap smoke test of the package: the manifest points at files that exist, the grammar compiles
// and recognizes the main constructs of the three syntaxes.

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const read = (file) => JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));

const manifest = read('package.json');
for (const grammar of manifest.contributes.grammars) {
  assert(fs.existsSync(path.join(root, grammar.path)), `${grammar.path} is missing`);
}
for (const language of manifest.contributes.languages) {
  assert(fs.existsSync(path.join(root, language.configuration)), `${language.configuration} is missing`);
}
assert(fs.existsSync(path.join(root, manifest.main)), 'the main file is missing');
for (const command of manifest.contributes.commands) {
  assert(command.command.startsWith('strig.'), `${command.command} is outside the strig namespace`);
}
read('language-configuration.json');

const grammar = read('syntaxes/strig.tmLanguage.json');
const repository = grammar.repository;
const matches = (rule) => new RegExp(rule.match || rule.begin, 'u');
for (const [name, rule] of Object.entries(repository)) {
  assert(rule.match || rule.begin, `${name} has no pattern`);
  matches(rule);
}
for (const pattern of grammar.patterns) {
  assert(repository[pattern.include.slice(1)], `${pattern.include} is not defined`);
}

const hit = (rule, text) => matches(repository[rule]).test(text);
assert(hit('language-line', 'language blocks'), 'language line');
assert(hit('language-line', 'language rules'), 'language line');
assert(hit('language-line', 'language actors'), 'language line');
assert(hit('declaration', 'permission org.read {'), 'permission declaration');
assert(hit('permission-id', 'depends_on = [document.view]'), 'permission id');
assert(hit('operator-word', 'subject.tags any_in ["docs"]'), 'text operator');
assert(hit('attribute-path', 'when = resource.name ends_with ".md"'), 'attribute path');
assert(hit('actor-ref', 'user:ana has role manager in project:apollo'), 'actor reference');
assert(hit('date', 'until 2026-12-31T23:59:59Z'), 'date');
assert(hit('comment', '  // a note'), 'comment');

console.log('strig vscode extension: smoke test passed');
