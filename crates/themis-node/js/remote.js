// Client for the Themis decision server (themis-server, contract in crates/themis-server/API.md).
// Every call fails closed: a network error, a timeout, any status other than 200, an unreadable body
// or an open circuit is a deny, never an allow, and no call throws.

const KNOWN_CODES = new Set([
  'malformed_json',
  'invalid_request',
  'batch_too_large',
  'too_many_resources',
  'not_found',
  'method_not_allowed',
  'body_too_large',
  'unsupported_media_type',
  'source_unavailable',
  'query_limit_exceeded',
  'overloaded',
  'relation_depth_exceeded',
  'deadline_exceeded',
  'clock_unavailable',
  'internal',
]);

/** Fixed texts per code, ours: the text a server sends is never echoed to the caller of the middleware. */
export const ERROR_MESSAGES = Object.freeze({
  source_unavailable: 'the grant source is unavailable; access is denied',
  invalid_request: 'the decision request was refused',
  deadline_exceeded: 'the decision was not ready in time; access is denied',
  overloaded: 'the decision service is overloaded; access is denied',
  internal: 'the decision could not be computed; access is denied',
});

/** @param {string} code */
export function messageFor(code) {
  return ERROR_MESSAGES[code] ?? 'the decision could not be computed; access is denied';
}

/** A code the client knows keeps its name; any other text becomes `{ unknown: text }`, never an error. */
export function parseErrorCode(value) {
  if (typeof value !== 'string' || value === '') return { unknown: '' };
  return KNOWN_CODES.has(value) ? value : { unknown: value };
}

const monotonic = () => performance.now();

/** Circuit breaker: closed, open for `waitMs`, then half-open with one probe. Each permit belongs to one generation. */
export class CircuitBreaker {
  /**
   * @param {{ failureThreshold?: number, waitMs?: number, clock?: () => number }} [options]
   */
  constructor(options = {}) {
    this.failureThreshold = positive(options.failureThreshold ?? 5, 'failureThreshold');
    this.waitMs = positive(options.waitMs ?? 30_000, 'waitMs');
    this.clock = options.clock ?? monotonic;
    this.state = 'closed';
    this.generation = 0;
    this.failures = 0;
    this.openedAt = 0;
    this.probing = false;
  }

  /** @returns {{ generation: number, probe: boolean } | null} null when the call is refused. */
  acquire() {
    if (this.state === 'closed') return { generation: this.generation, probe: false };
    if (this.state === 'open') {
      if (this.clock() - this.openedAt < this.waitMs) return null;
      this.#move('half-open');
      this.probing = true;
      return { generation: this.generation, probe: true };
    }
    if (this.probing) return null;
    this.probing = true;
    return { generation: this.generation, probe: true };
  }

  /** The server answered. A permit from an older generation is ignored: a late answer never closes the circuit. */
  success(permit) {
    if (permit.generation !== this.generation) return;
    if (this.state === 'half-open') this.#move('closed');
    this.failures = 0;
  }

  failure(permit) {
    if (permit.generation !== this.generation) return;
    if (this.state === 'half-open') return this.#open();
    this.failures += 1;
    if (this.failures >= this.failureThreshold) this.#open();
  }

  #open() {
    this.#move('open');
    this.openedAt = this.clock();
  }

  #move(state) {
    this.state = state;
    this.generation += 1;
    this.failures = 0;
    this.probing = false;
  }
}

function positive(value, name) {
  if (!Number.isFinite(value) || value <= 0) throw new TypeError(`${name} must be a positive number`);
  return value;
}

/**
 * @typedef {{ reason: string, status?: number, code?: string | { unknown: string }, message?: string }} Failure
 */

export class RemoteClient {
  /**
   * @param {object} options
   * @param {string} options.url base URL of the decision server
   * @param {number} [options.timeoutMs] per call, also sent as `x-themis-timeout-ms` (default 2000)
   * @param {typeof fetch} [options.fetch]
   * @param {Record<string, string>} [options.headers]
   * @param {{ failureThreshold?: number, waitMs?: number, clock?: () => number }} [options.breaker]
   */
  constructor(options) {
    if (typeof options?.url !== 'string' || options.url === '') throw new TypeError('url is required');
    this.base = options.url.replace(/\/+$/, '');
    this.timeoutMs = positive(options.timeoutMs ?? 2000, 'timeoutMs');
    this.fetch = options.fetch ?? globalThis.fetch?.bind(globalThis);
    if (typeof this.fetch !== 'function') throw new TypeError('no fetch available: pass options.fetch');
    this.headers = options.headers ?? {};
    this.breaker = new CircuitBreaker(options.breaker);
  }

  /**
   * One decision. `request` is `{ subject, permission, resource, env? }`.
   * @returns {Promise<{ allowed: boolean, decision?: object, evaluatedAt?: number, failure?: Failure }>}
   */
  async check(request) {
    const answer = await this.#call('/v1/check', request, (body) => validCheck(body));
    if (answer.failure) return { allowed: false, failure: answer.failure };
    return toResult(answer.body);
  }

  /** Many decisions in one call; the answers keep the request order. A failed call denies every check with the same failure. */
  async checkBatch(requests) {
    if (!Array.isArray(requests)) throw new TypeError('requests must be an array');
    if (requests.length === 0) return [];
    const answer = await this.#call('/v1/check/batch', { checks: requests }, (body) => {
      const results = body?.results;
      return Array.isArray(results) && results.length === requests.length && results.every(validCheck) ? results : null;
    });
    if (answer.failure) return requests.map(() => ({ allowed: false, failure: answer.failure }));
    return answer.body.map(toResult);
  }

  async #call(path, payload, validate) {
    const permit = this.breaker.acquire();
    if (!permit) return { failure: { reason: 'circuit_open' } };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let outcome;
    try {
      outcome = await this.#send(path, payload, controller.signal, validate);
    } catch (error) {
      outcome = { failure: controller.signal.aborted ? { reason: 'timeout' } : { reason: 'unreachable' }, cause: error };
    } finally {
      clearTimeout(timer);
    }
    // A 4xx means the server is alive and the caller's request is wrong: it does not count against the circuit.
    if (outcome.failure && outcome.failure.reason !== 'rejected') this.breaker.failure(permit);
    else this.breaker.success(permit);
    return outcome;
  }

  async #send(path, payload, signal, validate) {
    const response = await this.fetch(this.base + path, {
      method: 'POST',
      headers: {
        ...this.headers,
        'content-type': 'application/json',
        'x-themis-timeout-ms': String(Math.max(1, Math.ceil(this.timeoutMs))),
      },
      body: JSON.stringify(payload),
      signal,
    });
    const text = await response.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      body = undefined;
    }
    if (response.status !== 200) return { failure: failureOf(response.status, body) };
    const valid = body === undefined ? null : validate(body);
    if (!valid) return { failure: { reason: 'invalid_response', status: 200 } };
    return { body: valid === true ? body : valid };
  }
}

function failureOf(status, body) {
  const code = body?.error?.code === undefined ? undefined : parseErrorCode(body.error.code);
  const named = typeof code === 'string' ? { code, message: messageFor(code) } : code ? { code } : {};
  if (status >= 500) return { reason: 'server', status, ...named };
  if (status >= 400) return { reason: 'rejected', status, ...named };
  return { reason: 'unexpected_status', status, ...named };
}

function validCheck(body) {
  const effect = body?.decision?.effect;
  return effect === 'allow' || effect === 'deny';
}

function toResult(body) {
  return { allowed: body.decision.effect === 'allow', decision: body.decision, evaluatedAt: body.evaluated_at };
}
