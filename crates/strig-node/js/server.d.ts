import type { CapabilitySet, Context, Engine, Grant, Subject } from './index.js';
import type { Anchor, Change, ChangeKind, Resource, ServerMessage } from './protocol.js';

export interface Transport {
  publish(change: Change): Promise<void>;
  /** Devolve a função que cancela a assinatura. `onReset` avisa que mudanças podem ter se perdido. */
  subscribe(onChange: (change: Change) => void, onReset?: () => void): Promise<() => Promise<void> | void>;
}

export type Provider = (subject: Subject, scope: Resource) => Promise<CapabilitySet>;

export function change(kind: ChangeKind, scope: Anchor, extra?: Partial<Change>): Change;

export declare class Hub {
  constructor(options?: { origin?: string; transport?: Transport });
  readonly origin: string;
  subscribe(listener: (change: Change) => void): () => void;
  deliver(change: Change): void;
  publish(change: Change): Promise<Change>;
  startRelay(): Promise<void>;
  close(): Promise<void>;
}

export interface SessionOptions {
  hub: Hub;
  subject: Subject;
  scopes?: Resource[];
  provider?: Provider;
  heartbeatMs?: number;
}

export interface Session {
  ready: Promise<void>;
  handle(message: string | object): Promise<void>;
  close(): void;
}

export function openSession(options: SessionOptions & { send: (message: ServerMessage) => void }): Session;
export function sseResponse(options: SessionOptions): Response;
export function pipeSse(res: import('node:http').ServerResponse, options: SessionOptions): Session;
export function engineProvider(options: {
  engine: Engine;
  Context: typeof Context;
  loadGrants: (subject: Subject, scope: Resource) => Promise<Grant[]> | Grant[];
}): Provider;
export function memoryTransport(): Transport;
export function redisTransport(options: { publisher: unknown; subscriber: unknown; channel?: string }): Transport;
export function ioredisTransport(options: { publisher: unknown; subscriber: unknown; channel?: string }): Transport;
export function pgTransport(options: { client: unknown; listener: unknown; channel?: string }): Transport;
export function notify(queryable: { query(sql: string, params: unknown[]): Promise<unknown> }, channel: string, change: Change): Promise<void>;
