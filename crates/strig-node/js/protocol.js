// Formatos compartilhados com o crate strig-sync: escopo em texto, filtro de mudança e quadro SSE.

export const GLOBAL = 'global';

export function anchorToString(anchor) {
  return anchor.id == null ? anchor.kind : `${anchor.kind}:${anchor.id}`;
}

/** `document:d1/project:p1/org:o1`, igual a `strig_sync::scope_to_string`. */
export function scopeToString(scope) {
  return scope.path.map(anchorToString).join('/');
}

export function scopeFromString(text) {
  const path = text
    .split('/')
    .filter(Boolean)
    .map((segment) => {
      const at = segment.indexOf(':');
      return at < 0 ? { kind: segment } : { kind: segment.slice(0, at), id: segment.slice(at + 1) };
    });
  return { path };
}

export function sameAnchor(a, b) {
  return a.kind === b.kind && (a.id ?? null) === (b.id ?? null);
}

export function resourceContains(resource, anchor) {
  return anchor.kind === GLOBAL || resource.path.some((a) => sameAnchor(a, anchor));
}

/** Mesma regra de `Change::affects` no Rust. */
export function changeAffects(change, subjectId, scope) {
  if (change.kind === 'resync') return true;
  if (change.subject != null && change.subject !== subjectId) return false;
  return resourceContains(scope, change.scope);
}

/** O recurso está sob o escopo: o degrau principal do escopo aparece no caminho do recurso. */
export function resourceWithin(resource, scope) {
  const primary = scope.path[0];
  return primary === undefined || resourceContains(resource, primary);
}

export function encodeSse(message) {
  return `event: ${message.type}\ndata: ${JSON.stringify(message)}\n\n`;
}

/** Lê um stream de bytes SSE e chama `onMessage` com cada mensagem JSON. */
export async function readSse(body, onMessage) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buffer += decoder.decode(value, { stream: true }).replace(/\r\n?/g, '\n');
    let end;
    while ((end = buffer.indexOf('\n\n')) >= 0) {
      const block = buffer.slice(0, end);
      buffer = buffer.slice(end + 2);
      const data = block
        .split('\n')
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).replace(/^ /, ''))
        .join('\n');
      if (data) onMessage(JSON.parse(data));
    }
  }
}
