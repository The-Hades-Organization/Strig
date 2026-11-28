// The inspector page: shows why a decision came out the way it did, over the same engine the
// playground runs in WebAssembly. A scenario and a trail are read in the page; nothing is uploaded.
import { load } from './engine/browser.js';
import type { Strig } from '../crates/strig-node/js/dist/index.js';
import type { Explanation, Grant, Subject } from '../crates/strig-node/js/dist/index.js';
import { rulingOf } from './engine.js';
import type { Ruling, Step } from './engine.js';
import { Session, matrixChanges, parseScenario, parseTrail, replayRecord, verifyTrail } from './inspector-core.js';
import type { Effect, Resource, Trail } from './inspector-core.js';

const TABS = ['evaluation', 'matrix', 'audit'] as const;
type Tab = (typeof TABS)[number];
const isTab = (value: string | null): value is Tab => TABS.some((x) => x === value);
const SUBJECT_KINDS = ['user', 'role', 'principal', 'relation', 'any'] as const;
type MatcherKind = (typeof SUBJECT_KINDS)[number];
const isMatcherKind = (value: string): value is MatcherKind => SUBJECT_KINDS.some((x) => x === value);

interface State {
  tab: Tab;
  session: Session | null;
  subject: string;
  permission: string;
  resource: string;
  matrixResource: string;
  trail: Trail | null;
  onlyChanged: boolean;
}

const state: State = { tab: 'evaluation', session: null, subject: '', permission: '', resource: '', matrixResource: '', trail: null, onlyChanged: false };

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const found = document.getElementById(id);
  if (found === null) throw new Error(`#${id} is missing from inspector.html`);
  return found as T;
};
const el = {
  tabs: $('tabs'), rule: $('rule'), theme: $('theme'), info: $('scenario-info'), error: $('scenario-error'),
  paste: $<HTMLTextAreaElement>('paste-scenario'), pasteBox: $('paste-box'), file: $<HTMLInputElement>('file-scenario'),
  simBody: $('sim-body'),
};

let strig: Strig | null = null;
const engine = (): Strig => {
  if (strig === null) throw new Error('the engine is not loaded');
  return strig;
};
const session = (): Session | null => state.session;

/* ───────── Small DOM helpers ───────── */

function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string | boolean> = {}, ...kids: Array<Node | string>): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (typeof value === 'boolean') node.toggleAttribute(key, value);
    else node.setAttribute(key, value);
  }
  node.append(...kids);
  return node;
}

function icon(name: string): SVGSVGElement {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  s.setAttribute('class', 'i');
  s.setAttribute('aria-hidden', 'true');
  const u = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  u.setAttribute('href', '#i-' + name);
  s.appendChild(u);
  return s;
}

function withCode(text: string): DocumentFragment {
  const f = document.createDocumentFragment();
  text.split('`').forEach((part, i) => f.appendChild(i % 2 ? h('code', {}, part) : document.createTextNode(part)));
  return f;
}

function sealSvg(): Element {
  const NS = 'http://www.w3.org/2000/svg';
  const mk = (tag: string, attrs: Record<string, string | number>, parent?: Element): Element => {
    const n = document.createElementNS(NS, tag);
    Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, String(v)));
    if (parent) parent.appendChild(n);
    return n;
  };
  const s = mk('svg', { class: 'seal', viewBox: '0 0 64 64', 'aria-hidden': 'true' });
  const mask = mk('mask', { id: 'seal-cut', maskUnits: 'userSpaceOnUse', x: 0, y: -2, width: 64, height: 66 }, s);
  mk('rect', { x: 0, y: -2, width: 64, height: 66, fill: '#fff' }, mask);
  mk('path', { class: 'm-fangs', fill: '#000', d: 'M19.5 -1H28.5C28.5 15.5 27.3 26.72 25.5 32C23.7 26.72 19.5 15.5 19.5 -1Z M35.5 -1H44.5C44.5 15.5 40.3 26.72 38.5 32C36.7 26.72 35.5 15.5 35.5 -1Z' }, mask);
  mk('circle', { class: 'm-disc', cx: 32, cy: 32, r: 29, mask: 'url(#seal-cut)' }, s);
  return s;
}

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;
const word = (effect: Effect): string => (effect === 'allow' ? 'Allow' : 'Deny');
const ref = (anchor: { kind: string; id?: string }): string => (anchor.id === undefined ? anchor.kind : `${anchor.kind}:${anchor.id}`);
const message = (error: unknown): string => (error instanceof Error ? error.message : String(error));

function pill(effect: Effect, text = word(effect)): HTMLElement {
  return h('span', { class: 'pill', 'data-v': effect }, icon(effect === 'allow' ? 'check' : 'x'), text);
}

function select(label: string, id: string, options: string[], value: string, onChange: (value: string) => void): HTMLLabelElement {
  const control = h('select', { id });
  options.forEach((o) => control.append(h('option', { value: o }, o)));
  control.value = value;
  control.addEventListener('change', () => onChange(control.value));
  return h('label', { for: id }, label, control);
}

/* ───────── Scenario ───────── */

function showError(text: string | null): void {
  el.error.hidden = text === null;
  el.error.textContent = text ?? '';
}

function openScenario(text: string, origin: string): boolean {
  const parsed = parseScenario(text);
  if (!parsed.ok) {
    showError(`${origin}: ${parsed.message}`);
    return false;
  }
  const opened = Session.open(engine(), parsed.value, Date.now());
  if (!opened.ok) {
    showError(`${origin}: ${opened.message}`);
    return false;
  }
  showError(null);
  const next = opened.value;
  state.session = next;
  const subjects = Object.keys(next.scenario.subjects);
  const resources = Object.keys(next.scenario.resources);
  state.subject = subjects[0] ?? '';
  state.resource = resources[0] ?? '';
  state.matrixResource = state.resource;
  state.permission = next.permissions()[0] ?? '';
  el.info.textContent = `${origin}: ${plural(next.permissions().length, 'permission', 'permissions')}, ${plural(next.scenario.grants.length, 'grant', 'grants')}, ${plural(subjects.length, 'subject', 'subjects')}, ${plural(resources.length, 'resource', 'resources')}.`;
  renderAll();
  return true;
}

async function fetchText(path: string): Promise<string> {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.text();
}

async function loadExample(): Promise<void> {
  try {
    openScenario(await fetchText('examples/scenario.json'), 'example');
  } catch (error) {
    showError(message(error));
  }
}

/* ───────── Simulation ───────── */

function describeGrant(grant: Grant): string {
  const { subject } = grant;
  const who = subject.kind === 'any' ? 'anyone' : subject.kind === 'principal' ? `principal ${subject.name}` : subject.kind === 'relation' ? `relation ${subject.relation}` : `${subject.kind} ${subject.id}`;
  return `${grant.effect} ${grant.permission} on ${ref(grant.target)} for ${who}`;
}

function grantRow(s: Session, grant: Grant, added: boolean): HTMLElement {
  const off = !s.isEnabled(grant.id);
  const box = h('input', { type: 'checkbox', id: `g-${grant.id}` });
  box.checked = !off;
  box.addEventListener('change', () => { s.toggle(grant.id); renderAll(); });
  const li = h('li', { 'data-off': String(off), 'data-added': String(added) });
  li.append(box, h('label', { for: `g-${grant.id}` }, h('span', { class: 'gid' }, grant.id), h('span', { class: 'gdesc' }, describeGrant(grant))));
  if (added) {
    const drop = h('button', { class: 'btn small', type: 'button', 'aria-label': `Remove ${grant.id}` }, 'Remove');
    drop.addEventListener('click', () => { s.removeAdded(grant.id); renderAll(); });
    li.append(drop);
  } else {
    li.append(h('span'));
  }
  return li;
}

function addForm(s: Session): HTMLElement {
  const error = h('p', { class: 'note-bad', role: 'alert', hidden: true });
  const id = h('input', { type: 'text', id: 'add-id', autocomplete: 'off', spellcheck: 'false', placeholder: 'sim-1' });
  const effect = h('select', { id: 'add-effect' });
  ['allow', 'deny'].forEach((e) => effect.append(h('option', { value: e }, e)));
  const kind = h('select', { id: 'add-kind' });
  SUBJECT_KINDS.forEach((k) => kind.append(h('option', { value: k }, k)));
  const value = h('input', { type: 'text', id: 'add-value', autocomplete: 'off', spellcheck: 'false', list: 'add-values' });
  const values = h('datalist', { id: 'add-values' });
  const fill = (): void => {
    const names = kind.value === 'user' ? Object.entries(s.scenario.subjects).map(([name, subject]) => subject.id ?? name) : kind.value === 'role' ? s.roles() : [];
    values.replaceChildren(...names.map((n) => h('option', { value: n })));
    value.disabled = kind.value === 'any';
    if (value.disabled) value.value = '';
  };
  kind.addEventListener('change', fill);
  fill();
  const permission = h('select', { id: 'add-permission' });
  s.permissions().forEach((p) => permission.append(h('option', { value: p }, p)));
  const targetKind = h('select', { id: 'add-target-kind' });
  s.targetKinds().forEach((k) => targetKind.append(h('option', { value: k }, k)));
  const targetId = h('input', { type: 'text', id: 'add-target-id', autocomplete: 'off', spellcheck: 'false', placeholder: 'any' });

  const submit = h('button', { class: 'btn primary', type: 'button' }, 'Add to simulation');
  submit.addEventListener('click', () => {
    const matcher = kind.value;
    if (!isMatcherKind(matcher)) return;
    const named = value.value.trim();
    const refuse = (text: string): void => {
      error.textContent = text;
      error.hidden = false;
    };
    if (matcher !== 'any' && named === '') return refuse(`Name the ${matcher}.`);
    const subject: Grant['subject'] =
      matcher === 'any' ? { kind: 'any' } : matcher === 'principal' ? { kind: 'principal', name: named } : matcher === 'relation' ? { kind: 'relation', relation: named } : { kind: matcher, id: named };
    const target: Grant['target'] = targetId.value.trim() === '' ? { kind: targetKind.value } : { kind: targetKind.value, id: targetId.value.trim() };
    const result = s.add({ id: id.value.trim(), subject, permission: permission.value, target, effect: effect.value === 'deny' ? 'deny' : 'allow' });
    if (!result.ok) return refuse(result.message);
    renderAll();
  });

  const field = (text: string, control: HTMLElement, forId: string): HTMLLabelElement => h('label', { for: forId }, text, control);
  return h('details', { class: 'add' },
    h('summary', {}, 'Add a grant'),
    h('div', { class: 'addform' },
      h('div', { class: 'two' }, field('Id', id, 'add-id'), field('Effect', effect, 'add-effect')),
      h('div', { class: 'two' }, field('Subject', kind, 'add-kind'), field('Name', value, 'add-value')),
      values,
      field('Permission', permission, 'add-permission'),
      h('div', { class: 'two' }, field('Target kind', targetKind, 'add-target-kind'), field('Target id', targetId, 'add-target-id')),
      error,
      submit,
    ),
  );
}

function renderSimulation(): void {
  const s = session();
  if (s === null) {
    el.simBody.replaceChildren(h('p', { class: 'fine' }, 'Load a scenario to switch grants off or add some.'));
    return;
  }
  const list = h('ul', { class: 'grantlist', 'aria-label': 'Grants' });
  s.scenario.grants.forEach((g) => list.append(grantRow(s, g, false)));
  s.addedGrants().forEach((g) => list.append(grantRow(s, g, true)));
  const kids: Node[] = [list];
  if (s.scenario.grants.length === 0 && s.addedGrants().length === 0) kids.unshift(h('p', { class: 'fine' }, 'The scenario has no grants.'));
  const foot = h('div', { class: 'simfoot' });
  if (s.isSimulating()) {
    const changes = state.matrixResource in s.scenario.resources ? matrixChanges(s.matrix(state.matrixResource)).length : 0;
    const reset = h('button', { class: 'btn small', type: 'button' }, 'Reset');
    reset.addEventListener('click', () => { s.reset(); renderAll(); });
    foot.append(h('span', { class: 'pill', 'data-v': 'warn' }, 'Simulating'), h('span', { class: 'fine' }, `${plural(changes, 'cell changes', 'cells change')} on ${state.matrixResource}`), reset);
  } else {
    foot.append(h('span', { class: 'fine' }, 'Untick a grant to see the decisions without it.'));
  }
  kids.push(foot, addForm(s));
  el.simBody.replaceChildren(...kids);
}

/* ───────── Evaluation ───────── */

function stepList(steps: Step[], cite: string | null): HTMLElement {
  const ol = h('ol', { class: 'trace' });
  steps.forEach(([kind, text, id]) => {
    const body = h('span', {}, withCode(text));
    if (id !== undefined && id === cite) body.append(h('span', { class: 'pill decisive', 'data-v': 'warn' }, 'decisive'));
    ol.append(h('li', { class: kind }, icon(kind === 'ok' ? 'check' : kind === 'no' ? 'x' : 'dash'), body));
  });
  return ol;
}

const OVERRIDE_OUTCOME = { allowed: 'allowed it', denied: 'denied it', excepted: 'excepted this permission', abstained: 'did not apply' } as const;

function overrideSteps(explanation: Explanation): Step[] {
  return explanation.overrides.map((o): Step => [o.outcome === 'allowed' ? 'ok' : o.outcome === 'denied' ? 'no' : 'note', `Override \`${o.name}\`: ${OVERRIDE_OUTCOME[o.outcome]}.`]);
}

function verdictBox(ruling: Ruling): HTMLElement {
  const v = h('div', { class: 'verdict', role: 'group', 'aria-label': 'Ruling', 'data-v': ruling.verdict });
  v.append(sealSvg(), h('div', {}, h('p', { class: 'word' }, ruling.verdict === 'allow' ? 'Allow' : ruling.verdict === 'deny' ? 'Deny' : 'No ruling'), h('p', { class: 'why' }, withCode(ruling.headline))));
  return v;
}

/** A full account of one decision: ruling, path, roles, overrides and each grant. */
function explanationView(explanation: Explanation): HTMLElement {
  const ruling = rulingOf(explanation);
  const roles = explanation.roles.length === 0 ? 'none' : explanation.roles.map((r) => `\`${r}\``).join(', ');
  return h('div', {},
    verdictBox(ruling),
    h('dl', { class: 'facts' },
      h('dt', {}, 'Path'), h('dd', {}, h('code', {}, explanation.path.map(ref).join(' › '))),
      h('dt', {}, 'Roles'), h('dd', {}, withCode(roles)),
    ),
    h('p', { class: 'sect' }, 'How it was decided'),
    stepList([...overrideSteps(explanation), ...ruling.steps], ruling.cite),
  );
}

function renderEvaluation(): void {
  const pane = $('pane-evaluation');
  const s = session();
  if (s === null) {
    pane.replaceChildren(h('p', { class: 'fine' }, 'Load a scenario to ask why.'));
    return;
  }
  const grid = h('div', { class: 'field-grid' },
    select('Subject', 'sel-subject', Object.keys(s.scenario.subjects), state.subject, (v) => { state.subject = v; renderEvaluation(); }),
    select('Permission', 'sel-permission', s.permissions(), state.permission, (v) => { state.permission = v; renderEvaluation(); }),
    select('Resource', 'sel-resource', Object.keys(s.scenario.resources), state.resource, (v) => { state.resource = v; renderEvaluation(); }),
  );
  const subject: Subject | undefined = s.scenario.subjects[state.subject];
  const resource: Resource | undefined = s.scenario.resources[state.resource];
  if (subject === undefined || resource === undefined || state.permission === '') {
    pane.replaceChildren(grid, h('p', { class: 'empty' }, 'The scenario needs at least one subject, one resource and one permission.'));
    return;
  }
  try {
    const { now, before, changed } = s.compare(subject, state.permission, resource);
    const kids: Node[] = [grid, explanationView(now)];
    if (changed && before !== null) {
      kids.splice(1, 0, h('p', { class: 'was' }, h('span', { class: 'pill', 'data-v': 'warn' }, 'Changed'), h('span', {}, 'Originally ', pill(before.decision.effect), `, now ${word(now.decision.effect)}.`)));
    }
    pane.replaceChildren(...kids);
  } catch (error) {
    pane.replaceChildren(grid, h('p', { class: 'note-bad', role: 'alert' }, `The engine refused the question: ${message(error)}`));
  }
}

/* ───────── Matrix ───────── */

function renderMatrix(): void {
  const pane = $('pane-matrix');
  const s = session();
  if (s === null) {
    pane.replaceChildren(h('p', { class: 'fine' }, 'Load a scenario to see who can do what.'));
    return;
  }
  const picker = h('div', { class: 'field-grid' }, select('Resource', 'sel-matrix-resource', Object.keys(s.scenario.resources), state.matrixResource, (v) => { state.matrixResource = v; renderAll(); }));
  if (!(state.matrixResource in s.scenario.resources)) {
    pane.replaceChildren(picker, h('p', { class: 'empty' }, 'The scenario has no resources to build a matrix on.'));
    return;
  }
  const matrix = s.matrix(state.matrixResource);
  if (matrix.permissions.length === 0 || matrix.subjects.length === 0) {
    pane.replaceChildren(picker, h('p', { class: 'empty' }, 'The scenario needs permissions and subjects to build a matrix.'));
    return;
  }
  const head = h('tr', {}, h('th', { scope: 'col' }, 'Permission'));
  matrix.subjects.forEach((name) => head.append(h('th', { scope: 'col' }, name)));
  const body = h('tbody', {});
  matrix.permissions.forEach((permission, p) => {
    const row = h('tr', {}, h('th', { scope: 'row', title: permission }, permission));
    matrix.subjects.forEach((name, i) => {
      const effect = matrix.cells[p]?.[i] ?? 'deny';
      const was = matrix.baseline[p]?.[i] ?? 'deny';
      const changed = was !== effect;
      const button = h('button', { class: 'cellbtn', type: 'button', 'data-v': effect, 'data-changed': String(changed), 'aria-label': `${name}, ${permission}: ${word(effect)}${changed ? `, was ${word(was)}` : ''}. Open the evaluation.` },
        icon(effect === 'allow' ? 'check' : 'x'), word(effect));
      if (changed) button.append(h('small', {}, `was ${word(was)}`));
      button.addEventListener('click', () => {
        state.subject = name;
        state.permission = permission;
        state.resource = matrix.resource;
        renderEvaluation();
        setTab('evaluation');
      });
      row.append(h('td', {}, button));
    });
    body.append(row);
  });
  pane.replaceChildren(
    picker,
    h('div', { class: 'scroll', tabindex: '0', role: 'region', 'aria-label': `Access on ${matrix.resource}` }, h('table', { class: 'matrix' }, h('thead', {}, head), body)),
    h('p', { class: 'legendline' }, `Click a cell to open its evaluation.${s.isSimulating() ? ' Highlighted cells changed in the simulation.' : ''}`),
  );
}

/* ───────── Audit ───────── */

function chainBox(trail: Trail): HTMLElement {
  const status = verifyTrail(engine(), trail);
  if (status.kind === 'intact') {
    return h('div', { class: 'chain', 'data-v': 'ok', role: 'status' }, icon('check'),
      h('div', {}, h('b', {}, `Chain intact: ${plural(status.records, 'forensic record', 'forensic records')}.`), h('p', { class: 'fine' }, status.head === null ? '' : `Head ${status.head}`)));
  }
  if (status.kind === 'broken') {
    const where = status.line === null ? '' : ` at line ${status.line}`;
    return h('div', { class: 'chain', 'data-v': 'bad', role: 'alert' }, icon('bang'),
      h('div', {}, h('b', {}, `Chain broken${where}: ${status.code}.`), h('p', { class: 'fine' }, status.message)));
  }
  return h('div', { class: 'chain', 'data-v': 'none', role: 'status' }, icon('dash'),
    h('div', {}, h('b', {}, 'No forensic records.'), h('p', { class: 'fine' }, 'Only forensic records are chained, so there is nothing to verify.')));
}

function whenText(at: unknown): string {
  return typeof at === 'number' && Number.isFinite(at) ? `${new Date(at).toISOString().replace('T', ' ').slice(0, 19)} UTC` : 'no time';
}

function recordItem(s: Session, trail: Trail, index: number): HTMLElement | null {
  const record = trail.records[index];
  if (record === undefined) return null;
  const replay = replayRecord(s, record);
  if (state.onlyChanged && !(replay.kind === 'replayed' && replay.changed)) return null;
  const recorded: Effect = record.outcome === 'allowed' ? 'allow' : 'deny';
  const pills = h('span', { class: 'pills' }, pill(recorded, `was ${word(recorded)}`));
  if (replay.kind === 'replayed') {
    pills.append(pill(replay.explanation.decision.effect, `now ${word(replay.explanation.decision.effect)}`));
    if (replay.changed) pills.append(h('span', { class: 'pill', 'data-v': 'warn' }, 'would change'));
  } else {
    pills.append(h('span', { class: 'pill', 'data-v': 'mute' }, 'not replayable'));
  }
  const label = typeof record.object === 'string' ? record.object : String(record.action ?? 'record');
  const actor = typeof record.actor === 'string' ? record.actor : '';
  const details = h('details', { class: 'record', 'data-changed': String(replay.kind === 'replayed' && replay.changed) },
    h('summary', {}, h('span', { class: 'what' }, `${actor} · ${label}`), pills, h('span', { class: 'when' }, `line ${trail.lines[index]} · ${String(record.level ?? '')} · ${whenText(record.at)}`)),
  );
  details.append(h('div', { class: 'body' }, replay.kind === 'replayed' ? explanationView(replay.explanation) : h('p', { class: 'fine' }, `Not replayed: ${replay.reason}.`)));
  return details;
}

function loadTrail(text: string): void {
  state.trail = parseTrail(text);
  renderAudit();
}

function renderAudit(): void {
  const pane = $('pane-audit');
  const s = session();
  const example = h('button', { class: 'btn', type: 'button' }, 'Example trail');
  example.addEventListener('click', async () => {
    try { loadTrail(await fetchText('examples/audit.jsonl')); } catch (error) { showError(message(error)); }
  });
  const file = h('input', { class: 'sr', type: 'file', id: 'file-trail', accept: '.jsonl,.json,.txt,application/json', tabindex: '-1', 'aria-label': 'Trail file' });
  file.addEventListener('change', async () => {
    const chosen = file.files?.[0];
    if (chosen) loadTrail(await chosen.text());
  });
  const open = h('button', { class: 'btn', type: 'button' }, 'Open file');
  open.addEventListener('click', () => file.click());
  const paste = h('textarea', { id: 'paste-trail', rows: '3', spellcheck: 'false', 'aria-label': 'Trail JSON Lines', placeholder: 'Or paste records here, one per line (JSON Lines)' });
  const go = h('button', { class: 'btn', type: 'button' }, 'Load pasted');
  go.addEventListener('click', () => loadTrail(paste.value));
  const kids: Node[] = [
    h('p', { class: 'fine' }, 'Load a JSON Lines audit trail. The forensic chain is verified, and each detailed or forensic decision is asked again of the current policy, simulation included.'),
    h('div', { class: 'row gap' }, example, open, file),
    paste,
    h('div', { class: 'row gap' }, go),
  ];
  if (s === null) {
    kids.push(h('p', { class: 'empty' }, 'Load a scenario first: the decisions are replayed against its policy.'));
    pane.replaceChildren(...kids);
    return;
  }
  const trail = state.trail;
  if (trail === null) {
    pane.replaceChildren(...kids);
    return;
  }
  kids.push(chainBox(trail));
  if (trail.problems.length > 0) {
    const shown = trail.problems.slice(0, 3).map((p) => `line ${p.line} (${p.message})`).join('; ');
    kids.push(h('p', { class: 'note-bad', role: 'alert' }, `${plural(trail.problems.length, 'line was', 'lines were')} skipped: ${shown}${trail.problems.length > 3 ? '; …' : ''}.`));
  }
  const replayed = trail.records.map((r) => replayRecord(s, r)).filter((r) => r.kind === 'replayed');
  const changed = replayed.filter((r) => r.changed).length;
  const box = h('input', { type: 'checkbox', id: 'only-changed' });
  box.checked = state.onlyChanged;
  box.addEventListener('change', () => { state.onlyChanged = box.checked; renderAudit(); });
  kids.push(h('div', { class: 'toolbar' },
    h('span', { class: 'pill', 'data-v': changed > 0 ? 'warn' : 'allow' }, `${changed} of ${plural(replayed.length, 'replayed decision', 'replayed decisions')} would change`),
    h('label', { for: 'only-changed' }, box, 'Only those that would change'),
  ));
  const list = h('ul', { class: 'records', 'aria-label': 'Records' });
  trail.records.forEach((_, i) => {
    const item = recordItem(s, trail, i);
    if (item !== null) list.append(h('li', {}, item));
  });
  kids.push(list.childElementCount === 0 ? h('p', { class: 'empty' }, trail.records.length === 0 ? 'The trail has no records.' : 'No decision would change.') : list);
  pane.replaceChildren(...kids);
}

/* ───────── Frame ───────── */

function placeRule(): void {
  const b = el.tabs.querySelector<HTMLElement>('[aria-selected="true"]');
  if (!b) return;
  el.rule.style.width = b.offsetWidth + 'px';
  el.rule.style.transform = 'translateX(' + b.offsetLeft + 'px)';
}

function setTab(name: Tab): void {
  state.tab = name;
  el.tabs.querySelectorAll('button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
  document.querySelectorAll<HTMLElement>('.pane').forEach((p) => { p.dataset.on = String(p.id === 'pane-' + name); });
  placeRule();
}

function setTheme(t: 'light' | 'dark'): void {
  document.documentElement.dataset.theme = t;
  el.theme.replaceChildren(icon(t === 'dark' ? 'sun' : 'moon'));
  el.theme.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
}

function renderAll(): void {
  renderSimulation();
  renderEvaluation();
  renderMatrix();
  renderAudit();
}

function wire(): void {
  $('load-example').addEventListener('click', () => { void loadExample(); });
  $('load-file').addEventListener('click', () => el.file.click());
  el.file.addEventListener('change', async () => {
    const chosen = el.file.files?.[0];
    if (chosen) openScenario(await chosen.text(), chosen.name);
    el.file.value = '';
  });
  const toggle = $('load-paste');
  toggle.addEventListener('click', () => {
    const open = el.pasteBox.hidden;
    el.pasteBox.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
    if (open) el.paste.focus();
  });
  $('paste-go').addEventListener('click', () => {
    if (openScenario(el.paste.value, 'pasted')) {
      el.pasteBox.hidden = true;
      toggle.setAttribute('aria-expanded', 'false');
    }
  });
  el.tabs.addEventListener('click', (e) => {
    const next = (e.target as Element).closest<HTMLButtonElement>('button[data-tab]')?.dataset.tab ?? null;
    if (isTab(next)) setTab(next);
  });
  el.tabs.addEventListener('keydown', (e) => {
    const i = TABS.indexOf(state.tab);
    const n = e.key === 'ArrowRight' ? i + 1 : e.key === 'ArrowLeft' ? i - 1 : null;
    if (n === null) return;
    const name = TABS[(n + TABS.length) % TABS.length]!;
    setTab(name);
    $('tab-' + name).focus();
  });
  el.theme.addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
  window.addEventListener('resize', placeRule);
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(placeRule);
}

async function start(): Promise<void> {
  // State from the hash, e.g. #tab=matrix&theme=dark&sim=example&trail=example (the captures use it).
  const q = new URLSearchParams(location.hash.slice(1));
  const theme = q.get('theme');
  setTheme(theme === 'dark' || theme === 'light' ? theme : (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
  const tab = q.get('tab');
  setTab(isTab(tab) ? tab : 'evaluation');
  renderAll();
  try {
    strig = await load();
  } catch (error) {
    showError(`The WebAssembly engine could not be loaded: ${message(error)}. Serve this folder over HTTP instead of opening the file.`);
    return;
  }
  wire();
  await loadExample();
  const opened = session();
  if (q.get('sim') === 'example' && opened !== null) {
    opened.toggle('no-secret');
    state.resource = 'secret';
    state.matrixResource = 'secret';
    state.subject = 'ben';
    state.permission = 'document.view';
    renderAll();
  }
  if (q.get('trail') === 'example') {
    try { loadTrail(await fetchText('examples/audit.jsonl')); } catch { /* the example trail is optional */ }
  }
  placeRule();
  document.documentElement.dataset.ready = 'true';
}

void start();
