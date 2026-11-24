// The bridge between the page and the engine. Everything that comes out of here is what the
// WebAssembly build answered: the page keeps no copy of a rule, a verdict or a JSON document.

const SPEC_FIELDS = ['catalog', 'roles', 'relations', 'strategy', 'overrides', 'maxRelationDepth'];

// The binding reports where a problem starts, not how long it is; the span is the word there.
const WORD_AT = /^[^\s,[\]=()]+/;

/** @typedef {{ line: number | null, column: number | null, length: number, message: string, hint: string | null, related?: { line: number, column: number } }} Problem */

function toProblem(diagnostic, lines) {
  const { line, column, message, hint, related } = diagnostic;
  const at = line === null || column === null ? null : (lines[line - 1] ?? '').slice(column - 1);
  const word = at === null ? null : WORD_AT.exec(at);
  return { line, column, length: word ? word[0].length : 1, message, hint, related };
}

/**
 * Compiles a source with the engine's own parser and validator.
 * @returns {{ ok: true, policy: object, permissions: number, grants: number } | { ok: false, problems: Problem[] }}
 */
export function compileSource(strig, text) {
  try {
    const policy = strig.compile(text, { file: 'policy.strig' });
    return { ok: true, policy, permissions: policy.catalog.permissions.length, grants: (policy.grants ?? []).length };
  } catch (error) {
    if (!Array.isArray(error.diagnostics)) throw error;
    const lines = text.split('\n');
    return { ok: false, problems: error.diagnostics.map((d) => toProblem(d, lines)) };
  }
}

/** The text of `text` in another syntax, or `null` when it does not compile. */
export function convertSource(strig, text, language) {
  try {
    return strig.convert(text, language);
  } catch (error) {
    if (!Array.isArray(error.diagnostics)) throw error;
    return null;
  }
}

const ref = (anchor) => (anchor.id === undefined ? anchor.kind : `${anchor.kind}:${anchor.id}`);

function findSubject(policy, wanted) {
  if (typeof wanted !== 'string') return wanted;
  return (policy.subjects ?? []).find((s) => ref(s) === wanted) ?? null;
}

function subjectOf(policy, ask) {
  const found = findSubject(policy, ask.subject);
  if (found === null) return null;
  return ask.attrs ? { ...found, attrs: { ...found.attrs, ...ask.attrs } } : found;
}

const resourceOf = (ask) => ({ path: ask.path.map(([kind, id]) => ({ kind, id })) });

const literal = (value) => (typeof value === 'string' ? JSON.stringify(value) : String(value));

/** The one-line summary of a question: who, what, where. */
export function summarize(ask, policy) {
  const subject = policy ? subjectOf(policy, ask) : null;
  const who = ask.label ?? (typeof ask.subject === 'string' ? ask.subject : ref(ask.subject));
  const attrs = subject?.attrs ? Object.entries(subject.attrs).map(([k, v]) => `${k} = ${literal(v)}`) : [];
  const where = ask.path.map(([kind, id]) => `${kind}:${id}`).reverse().join(' > ');
  return `${who}${attrs.length ? ` (${attrs.join(', ')})` : ''} · ${ask.permission} · ${where}`;
}

const hold = (headline, note) => ({ verdict: 'hold', headline, cite: null, steps: note ? [['note', note]] : [] });

const STRATEGY_NOTE = {
  most_specific: () => 'the grant closest to the resource decides.',
  first_applicable: () => 'the first grant that applies decides; the ones after it are never reached.',
  deny_overrides: (effect) => (effect === 'deny' ? 'a matching deny beats every allow.' : 'no deny matched, so the allow stands.'),
  permit_overrides: (effect) => (effect === 'allow' ? 'a matching allow beats every deny.' : 'no allow matched, so the deny stands.'),
};

function headline(explanation) {
  const { decision } = explanation;
  const word = decision.effect === 'allow' ? 'Allowed' : 'Denied';
  const { reason } = decision;
  switch (reason.kind) {
    case 'grant': {
      const entry = explanation.grants.find((g) => g.grant.id === reason.grantId);
      const at = entry?.anchor ? `, matched at \`${ref(entry.anchor)}\`` : '';
      return { text: `${word} by grant \`${reason.grantId}\`${at}.`, cite: reason.grantId };
    }
    case 'override':
      return { text: `${word} by the override \`${reason.name}\`.`, cite: null };
    case 'missing_prerequisite':
      return { text: `Denied: \`${reason.permission}\` needs \`${reason.prerequisite}\`, which is not allowed here.`, cite: null };
    case 'unknown_permission':
      return { text: `Denied: the policy declares no permission \`${explanation.permission}\`.`, cite: null };
    case 'no_applicable_grant':
      return { text: 'Denied: no grant applies here.', cite: null };
    default:
      return { text: `${word}.`, cite: null };
  }
}

// What a grant that did not decide says about itself, one line each. A grant whose permission has
// nothing to do with the question is left out: it would only be noise.
function describeGrant(entry) {
  const { grant, verdict, condition } = entry;
  const id = `\`${grant.id}\``;
  const what = `\`${grant.permission}\` on \`${ref(grant.target)}\``;
  const scope = grant.scope ? `, in \`${ref(grant.scope)}\`` : '';
  switch (verdict.kind) {
    case 'candidate':
      return [grant.effect === 'allow' ? 'ok' : 'no', `${id} ${grant.effect === 'allow' ? 'allows' : 'denies'} ${what}${scope}.`, grant.id];
    case 'condition_false':
      return ['note', `${id} does not match: ${conditionText(condition)}`];
    case 'condition_unresolved':
    case 'subject_unresolved':
    case 'candidate_fail_safe':
      return ['no', `${id} could not be judged: ${verdict.problem}`];
    case 'subject_mismatch':
      return ['note', `${id} names another subject.`];
    case 'out_of_scope':
      return ['note', `${id} is scoped to \`${grant.scope ? ref(grant.scope) : 'elsewhere'}\`, outside this path.`];
    case 'target_not_on_path':
      return ['note', `${id} is on \`${ref(grant.target)}\`, which is not on the path of the resource.`];
    case 'outside_window':
      return ['note', `${id} is outside its validity window.`];
    case 'override_only':
      return ['note', `${id} is ignored: the permission is override-only.`];
    case 'not_reached':
      return ['note', `${id} is never reached.`];
    case 'permission_unrelated':
      return null;
    default:
      return null;
  }
}

// The condition trace names what failed; show the first leaf that is false.
function conditionText(trace) {
  if (!trace) return 'its condition is false.';
  const leaf = firstFalse(trace);
  return `\`${leaf.label}\` is false.`;
}

function firstFalse(trace) {
  const inner = (trace.children ?? []).find((c) => c.result.kind === 'false');
  return inner ? firstFalse(inner) : trace;
}

function roleSteps(explanation) {
  const { subject } = explanation;
  const who = `\`${ref(subject)}\``;
  const held = subject.roles ?? [];
  if (held.length === 0) return [['no', `${who} holds no role.`]];
  const named = held.map((r) => `\`${r.role}\`${r.scope ? ` in \`${ref(r.scope)}\`` : ''}`).join(', ');
  const direct = new Set(held.map((r) => r.role));
  const inherited = explanation.roles.filter((r) => !direct.has(r));
  const steps = [['ok', `${who} holds ${named}.`]];
  if (inherited.length) steps.push(['ok', `Through inheritance it also holds ${inherited.map((r) => `\`${r}\``).join(', ')}.`]);
  return steps;
}

function prerequisiteSteps(explanation) {
  return (explanation.prerequisites ?? []).map((p) => [
    p.allowed ? 'ok' : 'no',
    `\`${explanation.permission}\` needs \`${p.permission}\`: ${p.allowed ? 'allowed here' : 'not allowed here'}.`,
  ]);
}

/**
 * The engine's explanation of a question, as a ruling the page can show.
 * @returns {{ verdict: 'allow' | 'deny' | 'hold', headline: string, cite: string | null, steps: Array<[string, string, string?]> }}
 */
export function rule(strig, compiled, ask, now) {
  const subject = subjectOf(compiled.policy, ask);
  if (subject === null) {
    return hold(`The source has no subject \`${ask.subject}\`.`, 'Declare it, or pick another question.');
  }
  try {
    const { policy } = compiled;
    compiled.engine ??= new strig.Engine(Object.fromEntries(SPEC_FIELDS.filter((k) => policy[k] != null).map((k) => [k, policy[k]])));
    const context = new strig.Context({ grants: policy.grants ?? [], tuples: policy.tuples ?? [], now });
    const explanation = compiled.engine.explain(context, { subject, permission: ask.permission, resource: resourceOf(ask) });
    const { text, cite } = headline(explanation);
    const decided = explanation.decision.effect;
    const steps = [
      ...roleSteps(explanation),
      ...explanation.grants.map(describeGrant).filter((s) => s !== null),
      ...prerequisiteSteps(explanation),
      ['note', `Strategy \`${explanation.strategy}\`: ${STRATEGY_NOTE[explanation.strategy]?.(decided) ?? 'see the engine documentation.'}`],
    ];
    return { verdict: decided, headline: text, cite, steps };
  } catch (error) {
    if (typeof error.code !== 'string') throw error;
    return hold(`The engine refused the question: ${error.message}`, `Code \`${error.code}\`.`);
  }
}

/** The canonical JSON of a compiled policy, as the compiler produced it. */
export function canonicalJson(policy) {
  return JSON.stringify(policy, null, 2);
}
