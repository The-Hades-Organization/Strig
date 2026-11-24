// Syntax highlighting. The colour follows the role of a word in a decision, not its token class.
const KW = new Set(['language', 'kinds', 'broad', 'strategy', 'depth', 'permission', 'role', 'subject', 'grant', 'catalog', 'engine', 'override', 'always', 'tuple', 'relation', 'relations', 'target_kinds', 'broad_targets', 'assign', 'attrs']);
const REL = new Set(['inherits', 'implied', 'by', 'implied_by', 'depends_on', 'when', 'and', 'or', 'not', 'on', 'in', 'to', 'has', 'as', 'attr', 'principal', 'principals', 'anyone', 'label', 'targets', 'effect', 'scope', 'target', 'user', 'blocks', 'rules', 'actors', 'deny_overrides', 'first_applicable']);
const TOKEN = /(\/\/.*)|("[^"]*")|(\b(?:user|org|project|folder|document|doc|role|principal|group|team):[A-Za-z0-9_.-]+)|(\bg-[a-z0-9-]+)|(\b[a-z_]+\.[a-z_]+\b)|(\b[A-Za-z_][A-Za-z_0-9]*\b)|(\b\d+\b)|(==|>=|<=|!=|[<>])/g;

export function span(cls, text) {
  const s = document.createElement('span');
  if (cls) s.className = cls;
  s.textContent = text;
  return s;
}

export function highlightLine(line, errs) {
  const frag = document.createDocumentFragment();
  const pieces = [];
  let last = 0;
  TOKEN.lastIndex = 0;
  let m;
  while ((m = TOKEN.exec(line)) !== null) {
    if (m.index > last) pieces.push([null, last, m.index]);
    let cls = null;
    if (m[1]) cls = 't-com';
    else if (m[2]) cls = 't-str';
    else if (m[3]) cls = 't-ref';
    else if (m[4]) cls = 't-id';
    else if (m[5]) cls = 't-perm';
    else if (m[6]) cls = m[6] === 'allow' ? 't-allow' : m[6] === 'deny' ? 't-deny' : KW.has(m[6]) ? 't-kw' : REL.has(m[6]) ? 't-rel' : (m[6] === 'true' || m[6] === 'false') ? 't-num' : null;
    else if (m[7]) cls = 't-num';
    else if (m[8]) cls = 't-op';
    pieces.push([cls, m.index, m.index + m[0].length]);
    last = m.index + m[0].length;
  }
  if (last < line.length) pieces.push([null, last, line.length]);
  // split pieces at error boundaries so the squiggle covers exactly the token
  for (const [cls, a, b] of pieces) {
    const cuts = [a, b];
    for (const e of errs) { for (const p of [e.column - 1, e.column - 1 + e.length]) if (p > a && p < b) cuts.push(p); }
    cuts.sort((x, y) => x - y);
    for (let i = 0; i < cuts.length - 1; i++) {
      const x = cuts[i], y = cuts[i + 1];
      if (x === y) continue;
      const bad = errs.some((e) => x >= e.column - 1 && y <= e.column - 1 + e.length);
      frag.appendChild(span([cls, bad ? 't-err' : ''].filter(Boolean).join(' '), line.slice(x, y)));
    }
  }
  return frag;
}

