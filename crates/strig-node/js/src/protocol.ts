// Formatos compartilhados com o crate strig-sync: escopo em texto, filtro de mudança e quadro SSE.

export interface Anchor {
  kind: string;
  id?: string;
}

export interface Resource {
  path: Anchor[];
  attrs?: Record<string, unknown>;
}

export type ChangeKind = 'grants' | 'tuples' | 'roles' | 'catalog' | 'custom' | 'resync';

export interface Change {
  kind: ChangeKind;
  scope: Anchor;
  subject?: string;
  id?: string;
  origin: string;
  seq: number;
  at: number;
}

export type ServerMessage =
  | { type: 'hello'; origin: string; subject?: string }
  | { type: 'capabilities'; scope: Resource; set: { subject: unknown; grants: unknown[]; withFields?: unknown[] } }
  | { type: 'change'; change: Change }
  | { type: 'resync' }
  | { type: 'error'; message: string }
  | { type: 'ping' };

export type ClientMessage =
  | { type: 'watch'; scopes: Resource[] }
  | { type: 'unwatch'; scopes: Resource[] }
  | { type: 'refresh' };

export const GLOBAL = 'global';

export function anchorToString(anchor: Anchor): string {
  return anchor.id == null ? anchor.kind : `${anchor.kind}:${anchor.id}`;
}

/** `document:d1/project:p1/org:o1`, igual a `strig_sync::scope_to_string`. */
export function scopeToString(scope: Resource): string {
  return scope.path.map(anchorToString).join('/');
}

export function scopeFromString(text: string): Resource {
  const path = text
    .split('/')
    .filter(Boolean)
    .map((segment): Anchor => {
      const at = segment.indexOf(':');
      return at < 0 ? { kind: segment } : { kind: segment.slice(0, at), id: segment.slice(at + 1) };
    });
  return { path };
}

export function sameAnchor(a: Anchor, b: Anchor): boolean {
  return a.kind === b.kind && (a.id ?? null) === (b.id ?? null);
}

export function resourceContains(resource: Resource, anchor: Anchor): boolean {
  return anchor.kind === GLOBAL || resource.path.some((a) => sameAnchor(a, anchor));
}

/** Mesma regra de `Change::affects` no Rust. */
export function changeAffects(change: Change, subjectId: string | null, scope: Resource): boolean {
  if (change.kind === 'resync') return true;
  if (change.subject != null && change.subject !== subjectId) return false;
  return resourceContains(scope, change.scope);
}

/** O recurso está sob o escopo: o degrau principal do escopo aparece no caminho do recurso. */
export function resourceWithin(resource: Resource, scope: Resource): boolean {
  const primary = scope.path[0];
  return primary === undefined || resourceContains(resource, primary);
}

export function encodeSse(message: ServerMessage): string {
  return `event: ${message.type}\ndata: ${JSON.stringify(message)}\n\n`;
}

/** Lê um stream de bytes SSE e chama `onMessage` com cada mensagem JSON. */
export async function readSse(body: ReadableStream<Uint8Array>, onMessage: (message: ServerMessage) => void): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buffer += decoder.decode(value, { stream: true }).replace(/\r\n?/g, '\n');
    let end: number;
    while ((end = buffer.indexOf('\n\n')) >= 0) {
      const block = buffer.slice(0, end);
      buffer = buffer.slice(end + 2);
      const data = block
        .split('\n')
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).replace(/^ /, ''))
        .join('\n');
      if (data) onMessage(JSON.parse(data) as ServerMessage);
    }
  }
}
export * from './fields.js';
