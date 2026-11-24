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
  | { type: 'capabilities'; scope: Resource; set: { subject: unknown; grants: unknown[] } }
  | { type: 'change'; change: Change }
  | { type: 'resync' }
  | { type: 'error'; message: string }
  | { type: 'ping' };

export type ClientMessage =
  | { type: 'watch'; scopes: Resource[] }
  | { type: 'unwatch'; scopes: Resource[] }
  | { type: 'refresh' };

export const GLOBAL: 'global';
export function anchorToString(anchor: Anchor): string;
export function scopeToString(scope: Resource): string;
export function scopeFromString(text: string): Resource;
export function sameAnchor(a: Anchor, b: Anchor): boolean;
export function resourceContains(resource: Resource, anchor: Anchor): boolean;
export function changeAffects(change: Change, subjectId: string | null, scope: Resource): boolean;
export function resourceWithin(resource: Resource, scope: Resource): boolean;
export function encodeSse(message: ServerMessage): string;
export function readSse(body: ReadableStream<Uint8Array>, onMessage: (message: ServerMessage) => void): Promise<void>;
