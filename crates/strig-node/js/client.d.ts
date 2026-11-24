import type { Decision, Engine, Strig } from './index.js';
import type { Change, Resource, ServerMessage } from './protocol.js';

export interface PermissionClientOptions {
  url: string | URL;
  transport?: 'sse' | 'websocket';
  scopes?: Resource[];
  strig: Pick<Strig, 'Context'>;
  engine: Engine;
  headers?: Record<string, string>;
  fetch?: typeof fetch;
  WebSocket?: typeof WebSocket;
  reconnectMinMs?: number;
  reconnectMaxMs?: number;
}

export declare class PermissionClient {
  constructor(options: PermissionClientOptions);
  on(type: 'open', listener: (message: Extract<ServerMessage, { type: 'hello' }>) => void): () => void;
  on(type: 'capabilities', listener: (message: Extract<ServerMessage, { type: 'capabilities' }>) => void): () => void;
  on(type: 'change', listener: (change: Change) => void): () => void;
  on(type: 'resync' | 'disconnect' | 'close', listener: () => void): () => void;
  on(type: 'error', listener: (error: Error) => void): () => void;
  connect(): this;
  close(): void;
  watch(scopes: Resource[]): void;
  unwatch(scopes: Resource[]): void;
  capabilities(scope: Resource): unknown;
  decide(permission: string, resource: Resource): Decision;
  can(permission: string, resource: Resource): boolean;
}
