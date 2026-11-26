// Cliente de tempo real: recebe as capacidades do servidor por SSE ou WebSocket e decide localmente
// com o mesmo motor do servidor. Roda no navegador, no Node (>= 22 para WebSocket global) e no Bun.
import type { CapabilitySet, Context, Decision, Engine, PermissionArg, Strig } from './index.js';
import { readSse, resourceWithin, scopeToString, sameAnchor } from './protocol.js';
import type { Change, Resource, ServerMessage } from './protocol.js';

const sameScope = (a: Resource, b: Resource): boolean =>
  a.path.length === b.path.length && a.path.every((x, i) => sameAnchor(x, b.path[i]!));

export interface PermissionClientOptions {
  /** endpoint SSE ou WebSocket */
  url: string | URL;
  transport?: 'sse' | 'websocket';
  scopes?: Resource[];
  /** resultado de `load()` */
  strig: Pick<Strig, 'Context'>;
  /** motor montado com a mesma spec do servidor */
  engine: Engine;
  headers?: Record<string, string>;
  fetch?: typeof fetch;
  WebSocket?: typeof WebSocket;
  reconnectMinMs?: number;
  reconnectMaxMs?: number;
}

type HelloMessage = Extract<ServerMessage, { type: 'hello' }>;
type CapabilitiesMessage = Extract<ServerMessage, { type: 'capabilities' }>;

interface EventPayloads {
  open: HelloMessage;
  capabilities: CapabilitiesMessage;
  change: Change;
  resync: unknown;
  error: Error;
  disconnect: undefined;
  close: undefined;
}

type EventType = keyof EventPayloads;
type Listener = (payload: never) => void;

interface Entry {
  scope: Resource;
  set: CapabilitySet;
  context: Context;
}

export class PermissionClient<P extends string = string> {
  readonly url: string | URL;
  readonly transport: 'sse' | 'websocket';
  scopes: Resource[];
  readonly strig: Pick<Strig, 'Context'>;
  readonly engine: Engine<P>;
  readonly headers: Record<string, string>;
  readonly fetch: typeof fetch;
  readonly WebSocket: typeof WebSocket;
  readonly minDelay: number;
  readonly maxDelay: number;
  private entries = new Map<string, Entry>();
  private listeners = new Map<EventType, Set<Listener>>();
  private closed = true;
  private abort?: AbortController;
  private socket?: WebSocket;

  constructor(options: PermissionClientOptions) {
    this.url = options.url;
    this.transport = options.transport ?? 'sse';
    this.scopes = [...(options.scopes ?? [])];
    this.strig = options.strig;
    this.engine = options.engine;
    this.headers = options.headers ?? {};
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.WebSocket = options.WebSocket ?? globalThis.WebSocket;
    this.minDelay = options.reconnectMinMs ?? 500;
    this.maxDelay = options.reconnectMaxMs ?? 10_000;
  }

  on(type: 'open', listener: (message: HelloMessage) => void): () => void;
  on(type: 'capabilities', listener: (message: CapabilitiesMessage) => void): () => void;
  on(type: 'change', listener: (change: Change) => void): () => void;
  on(type: 'resync' | 'disconnect' | 'close', listener: () => void): () => void;
  on(type: 'error', listener: (error: Error) => void): () => void;
  on(type: EventType, listener: Listener): () => void {
    let set = this.listeners.get(type);
    if (!set) this.listeners.set(type, (set = new Set()));
    set.add(listener);
    return () => this.listeners.get(type)?.delete(listener);
  }

  private emit<T extends EventType>(type: T, payload: EventPayloads[T]): void {
    for (const listener of this.listeners.get(type) ?? []) (listener as (payload: EventPayloads[T]) => void)(payload);
  }

  connect(): this {
    if (!this.closed) return this;
    this.closed = false;
    void this.loop();
    return this;
  }

  close(): void {
    this.closed = true;
    this.abort?.abort();
    this.socket?.close();
  }

  watch(scopes: Resource[]): void {
    const fresh = scopes.filter((s) => !this.scopes.some((t) => sameScope(s, t)));
    if (!fresh.length) return;
    this.scopes.push(...fresh);
    this.resubscribe({ type: 'watch', scopes: fresh });
  }

  unwatch(scopes: Resource[]): void {
    this.scopes = this.scopes.filter((s) => !scopes.some((t) => sameScope(s, t)));
    for (const scope of scopes) this.entries.delete(scopeToString(scope));
    this.resubscribe({ type: 'unwatch', scopes });
  }

  private resubscribe(message: { type: 'watch' | 'unwatch'; scopes: Resource[] }): void {
    if (this.closed) return;
    if (this.transport === 'websocket' && this.socket?.readyState === 1) this.socket.send(JSON.stringify(message));
    else if (this.transport === 'sse') this.abort?.abort();
  }

  capabilities(scope: Resource): CapabilitySet | undefined {
    return this.entries.get(scopeToString(scope))?.set;
  }

  /** Decisão local. Sem capacidades de um escopo que contenha o recurso, nega. */
  decide(permission: PermissionArg<P>, resource: Resource): Decision {
    const entry = [...this.entries.values()].find((e) => resourceWithin(resource, e.scope));
    if (!entry) return { effect: 'deny', reason: { kind: 'no_applicable_grant' }, warnings: ['sem capacidades para o escopo'] };
    return this.engine.decide(entry.context, { subject: entry.set.subject, permission, resource });
  }

  can(permission: PermissionArg<P>, resource: Resource): boolean {
    return this.decide(permission, resource).effect === 'allow';
  }

  private handle(message: ServerMessage): void {
    switch (message.type) {
      case 'hello':
        return this.emit('open', message);
      case 'capabilities': {
        const context = new this.strig.Context();
        const set = message.set as CapabilitySet;
        context.loadCapabilities(set);
        this.entries.set(scopeToString(message.scope), { scope: message.scope, set, context });
        return this.emit('capabilities', message);
      }
      case 'change':
        return this.emit('change', message.change);
      case 'resync':
        this.entries.clear();
        return this.emit('resync', message);
      case 'error':
        return this.emit('error', new Error(message.message));
      default:
        return undefined;
    }
  }

  private async loop(): Promise<void> {
    let delay = this.minDelay;
    while (!this.closed) {
      const started = Date.now();
      try {
        if (this.transport === 'websocket') await this.runWebSocket();
        else await this.runSse();
      } catch (error) {
        if (!this.closed && (error as Error | undefined)?.name !== 'AbortError') this.emit('error', error as Error);
      }
      if (this.closed) break;
      this.emit('disconnect', undefined);
      if (Date.now() - started > this.maxDelay) delay = this.minDelay;
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * 2, this.maxDelay);
    }
    this.emit('close', undefined);
  }

  private async runSse(): Promise<void> {
    const url = new URL(this.url, globalThis.location?.href);
    for (const scope of this.scopes) url.searchParams.append('scope', scopeToString(scope));
    this.abort = new AbortController();
    const response = await this.fetch(url, {
      headers: { accept: 'text/event-stream', ...this.headers },
      signal: this.abort.signal,
    });
    if (!response.ok || !response.body) throw new Error(`SSE respondeu ${response.status}`);
    await readSse(response.body, (message) => this.handle(message));
  }

  private runWebSocket(): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = new this.WebSocket(String(this.url));
      this.socket = socket;
      socket.onopen = () => {
        if (this.scopes.length) socket.send(JSON.stringify({ type: 'watch', scopes: this.scopes }));
      };
      socket.onmessage = (event) => this.handle(JSON.parse(typeof event.data === 'string' ? event.data : String(event.data)) as ServerMessage);
      socket.onerror = (event) => reject((event as ErrorEvent | undefined)?.error ?? new Error('erro no WebSocket'));
      socket.onclose = () => resolve();
    });
  }
}
