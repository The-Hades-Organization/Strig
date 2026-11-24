// Cliente de tempo real: recebe as capacidades do servidor por SSE ou WebSocket e decide localmente
// com o mesmo motor do servidor. Roda no navegador, no Node (>= 22 para WebSocket global) e no Bun.
import { readSse, resourceWithin, scopeToString, sameAnchor } from './protocol.js';

const sameScope = (a, b) => a.path.length === b.path.length && a.path.every((x, i) => sameAnchor(x, b.path[i]));

export class PermissionClient {
  /**
   * @param {object} options
   * @param {string} options.url endpoint SSE ou WebSocket
   * @param {'sse' | 'websocket'} [options.transport]
   * @param {Array<{path: Array<{kind: string, id?: string}>}>} [options.scopes]
   * @param {{ Engine: any, Context: any }} options.strig resultado de `load()`
   * @param {any} options.engine motor montado com a mesma spec do servidor
   */
  constructor(options) {
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
    this.entries = new Map();
    this.listeners = new Map();
    this.closed = true;
  }

  on(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(listener);
    return () => this.listeners.get(type)?.delete(listener);
  }

  emit(type, payload) {
    for (const listener of this.listeners.get(type) ?? []) listener(payload);
  }

  connect() {
    if (!this.closed) return this;
    this.closed = false;
    this.loop();
    return this;
  }

  close() {
    this.closed = true;
    this.abort?.abort();
    this.socket?.close();
  }

  watch(scopes) {
    const fresh = scopes.filter((s) => !this.scopes.some((t) => sameScope(s, t)));
    if (!fresh.length) return;
    this.scopes.push(...fresh);
    this.resubscribe({ type: 'watch', scopes: fresh });
  }

  unwatch(scopes) {
    this.scopes = this.scopes.filter((s) => !scopes.some((t) => sameScope(s, t)));
    for (const scope of scopes) this.entries.delete(scopeToString(scope));
    this.resubscribe({ type: 'unwatch', scopes });
  }

  resubscribe(message) {
    if (this.closed) return;
    if (this.transport === 'websocket' && this.socket?.readyState === 1) this.socket.send(JSON.stringify(message));
    else if (this.transport === 'sse') this.abort?.abort();
  }

  capabilities(scope) {
    return this.entries.get(scopeToString(scope))?.set;
  }

  /** Decisão local. Sem capacidades de um escopo que contenha o recurso, nega. */
  decide(permission, resource) {
    const entry = [...this.entries.values()].find((e) => resourceWithin(resource, e.scope));
    if (!entry) return { effect: 'deny', reason: { kind: 'no_applicable_grant' }, warnings: ['sem capacidades para o escopo'] };
    return this.engine.decide(entry.context, { subject: entry.set.subject, permission, resource });
  }

  can(permission, resource) {
    return this.decide(permission, resource).effect === 'allow';
  }

  handle(message) {
    switch (message.type) {
      case 'hello':
        return this.emit('open', message);
      case 'capabilities': {
        const context = new this.strig.Context();
        context.loadCapabilities(message.set);
        this.entries.set(scopeToString(message.scope), { scope: message.scope, set: message.set, context });
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

  async loop() {
    let delay = this.minDelay;
    while (!this.closed) {
      const started = Date.now();
      try {
        if (this.transport === 'websocket') await this.runWebSocket();
        else await this.runSse();
      } catch (error) {
        if (!this.closed && error?.name !== 'AbortError') this.emit('error', error);
      }
      if (this.closed) break;
      this.emit('disconnect', undefined);
      if (Date.now() - started > this.maxDelay) delay = this.minDelay;
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * 2, this.maxDelay);
    }
    this.emit('close', undefined);
  }

  async runSse() {
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

  runWebSocket() {
    return new Promise((resolve, reject) => {
      const socket = new this.WebSocket(this.url);
      this.socket = socket;
      socket.onopen = () => {
        if (this.scopes.length) socket.send(JSON.stringify({ type: 'watch', scopes: this.scopes }));
      };
      socket.onmessage = (event) => this.handle(JSON.parse(typeof event.data === 'string' ? event.data : String(event.data)));
      socket.onerror = (event) => reject(event?.error ?? new Error('erro no WebSocket'));
      socket.onclose = () => resolve();
    });
  }
}
