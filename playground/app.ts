// The playground page. The source is compiled by the Strig engine (WebAssembly) on every edit,
// and the questions of a case are put to that same engine: nothing on the page decides anything.
import { load } from './engine/browser.js';
import type { Strig } from '../crates/strig-node/js/dist/index.js';
import { CASES } from './cases.js';
import type { Case } from './cases.js';
import { canonicalJson, compileSource, convertSource, rule, summarize } from './engine.js';
import type { Compiled, Problem, Syntax } from './engine.js';
import { highlightLine, span } from './highlight.js';

const SYNTAXES: readonly Syntax[] = ['blocks', 'rules', 'actors'];
const GRANT_ID = /^[A-Za-z0-9_.:-]{1,64}$/;
const TABS = ['evaluate', 'json', 'about'] as const;
type Tab = (typeof TABS)[number];
const isSyntax = (value: string | null): value is Syntax => SYNTAXES.some((x) => x === value);
const isTab = (value: string | null): value is Tab => TABS.some((x) => x === value);
const LINE_HEIGHT = 22; // px, the editor's line height in style.css

interface State {
  sc: number;
  syn: Syntax;
  tab: Tab;
  ask: number;
  cite: string | null;
  texts: Record<string, string>;
  compiled: Compiled | null;
  notice: string | null;
}

const state: State = { sc: 0, syn: 'rules', tab: 'evaluate', ask: 0, cite: null, texts: {}, compiled: null, notice: null };
const $ = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const found = document.getElementById(id);
  if (found === null) throw new Error(`#${id} is missing from index.html`);
  return found as T;
};
const el = { cases: $('cases'), seg: $('seg'), thumb: $('thumb'), status: $('status'), src: $<HTMLTextAreaElement>('src'), hl: $('hl'), gutter: $('gutter-in'), gutterBox: $('gutter'), problems: $('problems'), tabs: $('tabs'), rule: $('rule'), theme: $('theme') };

let strig: Strig | null = null;
function engine(): Strig {
  if (strig === null) throw new Error('the engine is not loaded');
  return strig;
}
function current(): Case { return CASES[state.sc]!; }
function textOf(): string {
  const k = state.sc + ':' + state.syn;
  let text = state.texts[k];
  if (text === undefined) {
    text = current().text[state.syn];
    state.texts[k] = text;
  }
  return text;
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
  text.split('`').forEach((part, i) => f.appendChild(i % 2 ? Object.assign(document.createElement('code'), { textContent: part }) : document.createTextNode(part)));
  return f;
}

/* ───────── Render: editor ───────── */

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;
const failure = (): Problem[] | null => (state.compiled !== null && !state.compiled.ok ? state.compiled.problems : null);
const hasProblems = (): boolean => failure() !== null;
const problemCount = (): number => failure()?.length ?? 0;

function problemButton(p: Problem): HTMLButtonElement {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'problem';
  const msg = document.createElement('span');
  msg.className = 'msg';
  msg.appendChild(withCode(p.message));
  b.append(icon('bang'), msg);
  if (p.line !== null) {
    const at = document.createElement('span');
    at.className = 'at';
    at.textContent = `policy.strig:${p.line}:${p.column}`;
    b.appendChild(at);
    const { line, column } = p;
    b.addEventListener('click', () => jump({ line, column: column ?? 1, length: p.length }));
  } else {
    b.disabled = true;
  }
  if (p.hint) {
    const hint = document.createElement('span');
    hint.className = 'hint';
    hint.appendChild(withCode(`hint: ${p.hint}`));
    b.appendChild(hint);
  }
  if (p.related) {
    const also = document.createElement('span');
    also.className = 'hint';
    also.textContent = `also at policy.strig:${p.related.line}:${p.related.column}`;
    b.appendChild(also);
  }
  return b;
}

/* ───────── Render: editor ───────── */
function renderEditor(): void {
  const text = el.src.value;
  const compiled = compileSource(engine(), text);
  state.compiled = compiled;
  const problems: Problem[] = compiled.ok ? [] : compiled.problems;
  const lines = text.split('\n');
  const wrap = document.createElement('span');
  wrap.className = 'wrap';
  const citePattern = state.cite ? wordPattern(state.cite) : null;
  const g = document.createDocumentFragment();
  lines.forEach((ln, i) => {
    const row = document.createElement('span');
    const lineErrs = problems.filter((e): e is Problem & { column: number } => e.line === i + 1 && e.column !== null);
    const cited = citePattern && citePattern.test(ln);
    row.className = 'l' + (cited ? ' cite' : '');
    row.appendChild(highlightLine(ln, lineErrs));
    wrap.appendChild(row);
    const n = document.createElement('div');
    n.textContent = String(i + 1);
    if (cited) n.className = 'cite';
    if (lineErrs.length) n.className = 'bad';
    g.appendChild(n);
  });
  el.hl.replaceChildren(wrap);
  el.gutter.replaceChildren(g);
  syncScroll();

  el.status.dataset.bad = String(problems.length > 0);
  el.status.replaceChildren(icon(problems.length ? 'bang' : 'check'), document.createTextNode(
    problems.length ? plural(problems.length, 'problem', 'problems')
      : compiled.ok ? `Compiles: ${plural(compiled.permissions, 'permission', 'permissions')}, ${plural(compiled.grants, 'grant', 'grants')}`
        : plural(problems.length, 'problem', 'problems')));

  const box = el.problems;
  box.replaceChildren();
  if (state.notice) {
    const note = document.createElement('div');
    note.className = 'none';
    note.append(icon('bang'), document.createTextNode(state.notice));
    box.appendChild(note);
  }
  if (!problems.length) {
    const none = document.createElement('div');
    none.className = 'none';
    none.append(icon('check'), document.createTextNode('No problems.'));
    box.appendChild(none);
  }
  problems.forEach((p) => box.appendChild(problemButton(p)));
  renderEvaluate();
  renderJson();
}

function syncScroll(): void {
  el.hl.scrollTop = el.src.scrollTop;
  el.hl.scrollLeft = el.src.scrollLeft;
  el.gutter.style.transform = 'translateY(' + (-el.src.scrollTop) + 'px)';
}

// Matches a grant id as a whole word. The id is escaped in full: it can come from the URL hash.
function wordPattern(id: string): RegExp {
  return new RegExp('(^|[^\\w-])' + id.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&') + '($|[^\\w-])');
}

interface JumpTarget {
  line: number | null;
  column: number;
  length: number;
}

function jump(p: JumpTarget): void {
  if (p.line === null) return;
  const lines = el.src.value.split('\n');
  let off = 0;
  for (let i = 0; i < p.line - 1; i++) off += (lines[i] ?? '').length + 1;
  el.src.focus({ preventScroll: true });
  el.src.setSelectionRange(off + p.column - 1, off + p.column - 1 + p.length);
  el.src.scrollTop = Math.max(0, (p.line - 3) * LINE_HEIGHT);
  syncScroll();
}

function jumpToGrant(id: string): void {
  const lines = el.src.value.split('\n');
  const re = wordPattern(id);
  const i = lines.findIndex((l) => re.test(l));
  if (i < 0) return;
  jump({ line: i + 1, column: (lines[i] ?? '').indexOf(id) + 1, length: id.length });
}

/* ───────── Render: ruling ───────── */
function sealSvg(): Element {
  const NS = 'http://www.w3.org/2000/svg';
  const mk = (tag: string, attrs: Record<string, string | number>, parent?: Element): Element => { const n = document.createElementNS(NS, tag); Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, String(v))); if (parent) parent.appendChild(n); return n; };
  const s = mk('svg', { class: 'seal', viewBox: '0 0 64 64', 'aria-hidden': 'true' });
  const mask = mk('mask', { id: 'seal-cut', maskUnits: 'userSpaceOnUse', x: 0, y: -2, width: 64, height: 66 }, s);
  mk('rect', { x: 0, y: -2, width: 64, height: 66, fill: '#fff' }, mask);
  mk('path', { class: 'm-fangs', fill: '#000', d: 'M19.5 -1H28.5C28.5 15.5 27.3 26.72 25.5 32C23.7 26.72 19.5 15.5 19.5 -1Z M35.5 -1H44.5C44.5 15.5 40.3 26.72 38.5 32C36.7 26.72 35.5 15.5 35.5 -1Z' }, mask);
  mk('circle', { class: 'm-disc', cx: 32, cy: 32, r: 29, mask: 'url(#seal-cut)' }, s);
  return s;
}

function renderEvaluate(): void {
  const pane = $('pane-evaluate');
  const c = current();
  const prevScroll = pane.scrollTop;
  const kids: Node[] = [];
  const policy = state.compiled && state.compiled.ok ? state.compiled.policy : null;

  const list = document.createElement('ul');
  list.className = 'asks';
  list.setAttribute('aria-label', 'Questions');
  c.asks.forEach((a, i) => {
    const li = document.createElement('li');
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'ask';
    b.setAttribute('aria-pressed', String(i === state.ask));
    const t = document.createElement('b');
    t.textContent = a.title;
    const s = document.createElement('span');
    s.textContent = summarize(a, policy);
    b.append(t, s);
    b.addEventListener('click', () => { state.ask = i; state.cite = null; renderEditor(); });
    li.appendChild(b);
    list.appendChild(li);
  });
  kids.push(list);

  const bad = hasProblems();
  const ruling = bad || state.compiled === null ? null : rule(engine(), state.compiled, c.asks[state.ask] ?? c.asks[0]!, Date.now());
  const v = document.createElement('div');
  v.className = 'verdict';
  v.setAttribute('role', 'group');
  v.setAttribute('aria-label', 'Ruling');
  const word = document.createElement('p');
  word.className = 'word';
  const why = document.createElement('p');
  why.className = 'why';
  if (bad) {
    v.dataset.v = 'hold';
    word.textContent = 'No ruling';
    const n = problemCount();
    why.textContent = `The source has ${plural(n, 'problem', 'problems')}. Fix ${n === 1 ? 'it' : 'them'} and the question is answered.`;
  } else {
    v.dataset.v = ruling!.verdict;
    word.textContent = ruling!.verdict === 'allow' ? 'Allow' : ruling!.verdict === 'deny' ? 'Deny' : 'No ruling';
    why.appendChild(withCode(ruling!.headline));
  }
  const txt = document.createElement('div');
  txt.append(word, why);
  v.append(sealSvg(), txt);
  v.dataset.key = [state.sc, state.ask, v.dataset.v].join('.');
  kids.push(v);

  if (ruling) {
    const ol = document.createElement('ol');
    ol.className = 'trace';
    ruling.steps.forEach(([k, t, cite]) => {
      const li = document.createElement('li');
      li.className = k;
      const p = document.createElement('span');
      p.appendChild(withCode(t));
      if (cite) {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'cite';
        b.append(icon('line'), document.createTextNode('Show ' + cite));
        b.addEventListener('click', () => { state.cite = cite; renderEditor(); jumpToGrant(cite); });
        p.appendChild(b);
      }
      li.append(icon(k === 'ok' ? 'check' : k === 'no' ? 'x' : 'dash'), p);
      ol.appendChild(li);
    });
    kids.push(ol);
  } else {
    const p = document.createElement('p');
    p.className = 'hold-note';
    p.textContent = 'Select a problem below the editor to jump to it.';
    kids.push(p);
  }
  pane.replaceChildren(...kids);
  pane.scrollTop = prevScroll;
}

const KEYS = /("(?:[^"\\]|\\.)*")(\s*:)|("(?:[^"\\]|\\.)*")|\b(true|false|null)\b|(-?\d+(?:\.\d+)?)/g;
function renderJson(): void {
  const pane = $('pane-json');
  if (hasProblems()) {
    pane.replaceChildren(Object.assign(document.createElement('p'), { className: 'fine', textContent: 'There is no policy to show yet: the source has problems. Fix them and the canonical JSON appears here.' }));
    return;
  }
  if (state.compiled === null || !state.compiled.ok) return;
  const json = canonicalJson(state.compiled.policy);
  const pre = document.createElement('pre');
  pre.className = 'json';
  json.split('\n').forEach((ln, i, all) => {
    let last = 0;
    let m: RegExpExecArray | null;
    KEYS.lastIndex = 0;
    while ((m = KEYS.exec(ln)) !== null) {
      if (m.index > last) pre.appendChild(document.createTextNode(ln.slice(last, m.index)));
      if (m[1]) { pre.appendChild(span('t-kw', m[1])); pre.appendChild(document.createTextNode(m[2] ?? '')); }
      else if (m[3]) pre.appendChild(span(/^"(allow)"$/.test(m[3]) ? 't-allow' : /^"(deny)"$/.test(m[3]) ? 't-deny' : 't-str', m[3]));
      else pre.appendChild(span('t-num', m[0]));
      last = m.index + m[0].length;
    }
    pre.appendChild(document.createTextNode(ln.slice(last) + (i < all.length - 1 ? '\n' : '')));
  });
  pane.replaceChildren(pre);
}

function renderAbout(): void {
  const pane = $('pane-about');
  const h = (t: string) => Object.assign(document.createElement('h2'), { textContent: t });
  const p = (t: string, c?: string) => Object.assign(document.createElement('p'), { textContent: t, className: c || '' });
  const kinds = document.createElement('ul');
  kinds.className = 'kinds';
  ([['Blocks', 'explicit and regular, a block per declaration. Suits generated files and large policies.'],
   ['Rules', 'one statement per line, written to be read aloud. Suits short policies and review.'],
   ['Actors', 'grouped by who acts. Suits answering what an editor can do.']] as Array<[string, string]>).forEach(([n, d]) => {
    const li = document.createElement('li');
    li.append(Object.assign(document.createElement('b'), { textContent: n + ': ' }), document.createTextNode(d));
    kinds.appendChild(li);
  });
  const legend = document.createElement('dl');
  legend.className = 'legend';
  ([['t-kw', 'permission', 'declares something'], ['t-rel', 'depends_on  inherits  when', 'relates things'], ['t-ref', 'user:ana  org:acme', 'who, and where'],
   ['t-perm', 'document.edit', 'what is asked'], ['t-allow', 'allow', 'an allow'], ['t-deny', 'deny', 'a deny'], ['t-err', 'doc.write', 'a problem']] as Array<[string, string, string]>).forEach(([c, s, d]) => {
    const dt = document.createElement('dt');
    dt.appendChild(span(c, s));
    legend.append(dt, Object.assign(document.createElement('dd'), { textContent: d }));
  });
  pane.replaceChildren(
    h('Three ways to write one policy'),
    p('A policy is data. The text form has three syntaxes that parse to the same policy. Switch between them above the editor; the case stays the same, and what you typed is converted.'),
    kinds,
    Object.assign(h('How to read the colours'), { className: 'gap-top' }),
    p('Colour follows the role a word plays in a decision, not its token class.', 'fine'),
    legend,
    Object.assign(h('What is real here'), { className: 'gap-top' }),
    p('All of it. The page compiles your source with the Strig engine, built to WebAssembly, and puts the questions of the case to the same engine. The problems, the rulings and the JSON are what it answers; the page decides nothing. Dates are UTC.', 'fine')
  );
}

/* ───────── Wiring ───────── */
function renderCases(): void {
  el.cases.replaceChildren();
  CASES.forEach((c, i) => {
    const li = document.createElement('li');
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'case';
    b.setAttribute('aria-current', String(i === state.sc));
    if (c.flaw) b.dataset.flaw = 'true';
    b.append(Object.assign(document.createElement('b'), { textContent: c.title }), Object.assign(document.createElement('span'), { textContent: c.desc }));
    b.addEventListener('click', () => { state.sc = i; state.ask = 0; state.cite = null; state.notice = null; loadText(); renderCases(); });
    li.appendChild(b);
    el.cases.appendChild(li);
  });
}

function placeThumb(): void {
  const b = el.seg.querySelector<HTMLElement>('[aria-pressed="true"]');
  if (!b) return;
  el.thumb.style.width = b.offsetWidth + 'px';
  el.thumb.style.transform = 'translateX(' + (b.offsetLeft - 3) + 'px)';
}

function placeRule(): void {
  const b = el.tabs.querySelector<HTMLElement>('[aria-selected="true"]');
  if (!b) return;
  el.rule.style.width = b.offsetWidth + 'px';
  el.rule.style.transform = 'translateX(' + b.offsetLeft + 'px)';
}

function loadText(): void {
  el.src.value = textOf();
  el.src.scrollTop = 0;
  el.src.scrollLeft = 0;
  renderEditor();
}

// Switching syntax converts what is on screen when the engine can read it. A text that has problems
// cannot be converted, so the target keeps the last text it had, and the page says so.
function switchSyntax(next: Syntax): void {
  const from = state.syn;
  const text = el.src.value;
  state.texts[`${state.sc}:${from}`] = text;
  const edited = text !== current().text[from];
  const converted = edited ? convertSource(engine(), text, next) : null;
  state.notice = edited && converted === null
    ? `The source has problems, so it could not be converted to ${next}. This is the last ${next} text.`
    : null;
  if (converted !== null) state.texts[`${state.sc}:${next}`] = converted;
  else if (!edited) delete state.texts[`${state.sc}:${next}`];
  state.syn = next;
  state.cite = null;
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

function wire(): void {
  el.src.addEventListener('input', () => { state.texts[state.sc + ':' + state.syn] = el.src.value; state.cite = null; state.notice = null; renderEditor(); });
  el.src.addEventListener('scroll', syncScroll);

  el.seg.addEventListener('click', (e) => {
    const b = (e.target as Element).closest<HTMLButtonElement>('button[data-syn]');
    const next = b?.dataset.syn ?? null;
    if (!b || !isSyntax(next) || next === state.syn) return;
    switchSyntax(next);
    el.seg.querySelectorAll('button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
    placeThumb();
    loadText();
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
  window.addEventListener('resize', () => { placeThumb(); placeRule(); });
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => { placeThumb(); placeRule(); });
}

function failed(error: unknown): void {
  el.status.dataset.bad = 'true';
  el.status.replaceChildren(icon('bang'), document.createTextNode('The engine did not load'));
  el.problems.replaceChildren(Object.assign(document.createElement('div'), { className: 'none', textContent: `The WebAssembly engine could not be loaded: ${error instanceof Error ? error.message : String(error)}. Serve this folder over HTTP (node playground/serve.mjs) instead of opening the file.` }));
}

async function start(): Promise<void> {
  // Start state from the hash, e.g. #case=3&syn=actors&tab=json&ask=1&theme=dark (the captures use it).
  const q = new URLSearchParams(location.hash.slice(1));
  if (q.has('case')) state.sc = Math.min(CASES.length - 1, Math.max(0, Number(q.get('case')) || 0));
  const syn = q.get('syn');
  if (isSyntax(syn)) { state.syn = syn; el.seg.querySelectorAll('button').forEach((x) => x.setAttribute('aria-pressed', String(x.dataset.syn === state.syn))); }
  if (q.has('ask')) state.ask = Math.min(current().asks.length - 1, Math.max(0, Number(q.get('ask')) || 0));
  const theme = q.get('theme');
  setTheme(theme === 'dark' || theme === 'light' ? theme : (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
  renderAbout();
  const tab = q.get('tab');
  setTab(isTab(tab) ? tab : 'evaluate');
  placeThumb();
  try {
    strig = await load();
  } catch (error) {
    failed(error);
    return;
  }
  wire();
  renderCases();
  loadText();
  if (GRANT_ID.test(q.get('fix') ?? '')) { state.cite = q.get('fix'); renderEditor(); }
  document.documentElement.dataset.ready = 'true';
}

start().catch(failed);
