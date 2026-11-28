package io.github.thehadesorganization.strig;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The Strig engine over an EngineSpec. Arguments are anything Jackson turns into the same JSON the
 * Rust, JavaScript and Python APIs take (maps, lists, records, {@link JsonNode}); results are the
 * same JSON as maps, lists and {@link Decision}.
 *
 * <p>Safe for concurrent use: calls are serialized, because a WebAssembly instance is
 * single-threaded. For parallel throughput give each worker its own engine with {@link #fork()}.
 * Kotlin uses this same class.
 */
public final class Engine implements AutoCloseable {
  private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {};
  private static final TypeReference<List<Map<String, Object>>> MAPS = new TypeReference<>() {};
  private static final TypeReference<List<Boolean>> BOOLS = new TypeReference<>() {};

  private final JsonNode spec;
  private final Wasm wasm;
  private final long handle;
  private boolean closed;

  public Engine(Object spec) {
    this(Wasm.JSON.valueToTree(spec));
  }

  private Engine(JsonNode spec) {
    this.spec = spec;
    this.wasm = new Wasm();
    this.handle = wasm.invoke("engine.new", args("spec", spec)).asLong();
  }

  /** An independent engine over the same spec, with its own instance, for another thread. */
  public Engine fork() {
    return new Engine(spec);
  }

  /** Creates a context with no grants, tuples or environment. */
  public Context newContext() {
    return newContext(null);
  }

  /** Creates a context from the optional {@code {grants, tuples, env, now, limits}} object. */
  public Context newContext(Object init) {
    Map<String, Object> a = new HashMap<>();
    a.put("init", init);
    return new Context(this, call("context.new", a).asLong());
  }

  /** Whether {@code request} is allowed. A failure to decide is an exception, never {@code true}. */
  public boolean check(Context context, Object request) {
    return check(context, request, null);
  }

  public boolean check(Context context, Object request, Instant now) {
    return decisionCall("check", context, "request", request, now).asBoolean();
  }

  public Decision decide(Context context, Object request) {
    return decide(context, request, null);
  }

  public Decision decide(Context context, Object request, Instant now) {
    return Wasm.JSON.convertValue(decisionCall("decide", context, "request", request, now), Decision.class);
  }

  public Map<String, Object> explain(Context context, Object request) {
    return explain(context, request, null);
  }

  public Map<String, Object> explain(Context context, Object request, Instant now) {
    return Wasm.JSON.convertValue(decisionCall("explain", context, "request", request, now), MAP);
  }

  public List<Boolean> checkMany(Context context, Object requests) {
    return checkMany(context, requests, null);
  }

  public List<Boolean> checkMany(Context context, Object requests, Instant now) {
    return Wasm.JSON.convertValue(decisionCall("checkMany", context, "requests", requests, now), BOOLS);
  }

  /**
   * What {@code subject} can reach with {@code permission} over resources of {@code kind};
   * {@code options} is the optional {@code {layout, resources}} object.
   */
  public Map<String, Object> list(Context context, Object subject, String permission, String kind, Object options) {
    Map<String, Object> a = new HashMap<>();
    a.put("subject", subject);
    a.put("permission", permission);
    a.put("kind", kind);
    a.put("options", options);
    return Wasm.JSON.convertValue(contextCall("list", context, a), MAP);
  }

  /** The parties some allow grant gives {@code permission} to. */
  public List<Map<String, Object>> whoCan(Context context, String permission) {
    Map<String, Object> a = new HashMap<>();
    a.put("permission", permission);
    return Wasm.JSON.convertValue(contextCall("whoCan", context, a), MAPS);
  }

  /** The permission catalog of the spec. */
  public Map<String, Object> catalog() {
    return Wasm.JSON.convertValue(call("catalog", new HashMap<>()), MAP);
  }

  /**
   * Applies a grant or role change through the invariants: {@code {ok, grants?, subject?,
   * violations?, audit?}}. When the input has no {@code now}, the host clock fills it.
   */
  public Map<String, Object> apply(Object input) {
    return change("apply", input);
  }

  /** What a change would do to access ({@code {ok, impact?, violations?}}), without applying it. */
  public Map<String, Object> impact(Object input) {
    return change("impact", input);
  }

  /** The impact of a pending request as proposed and as it would be now. */
  public Map<String, Object> reviewImpact(Object input) {
    return change("reviewImpact", input);
  }

  public Map<String, Object> propose(Object input) {
    return change("propose", input);
  }

  public Map<String, Object> resolve(Object input) {
    return change("resolve", input);
  }

  public Map<String, Object> expire(Object input) {
    return change("expire", input);
  }

  @Override
  public synchronized void close() {
    closed = true;
    wasm.close();
  }

  synchronized boolean isClosed() {
    return closed;
  }

  private Map<String, Object> change(String op, Object input) {
    JsonNode node = Wasm.JSON.valueToTree(input);
    Map<String, Object> a = new HashMap<>();
    a.put("input", node);
    if (node.path("now").isNull() || node.path("now").isMissingNode()) {
      a.put("now", Instant.now().toEpochMilli());
    }
    return Wasm.JSON.convertValue(call(op, a), MAP);
  }

  private JsonNode decisionCall(String op, Context context, String name, Object value, Instant now) {
    Map<String, Object> a = new HashMap<>();
    a.put(name, value);
    if (now != null) {
      a.put("now", now.toEpochMilli());
    }
    return contextCall(op, context, a);
  }

  JsonNode contextCall(String op, Context context, Map<String, Object> a) {
    if (context == null || context.engine() != this) {
      throw new StrigException("INVALID_ARGUMENT", "context belongs to another engine");
    }
    if (context.isClosed()) {
      throw new StrigException("INVALID_ARGUMENT", "engine or context is closed");
    }
    a.put("context", context.handle());
    return call(op, a);
  }

  synchronized JsonNode call(String op, Map<String, Object> a) {
    if (closed) {
      throw new StrigException("INVALID_ARGUMENT", "engine or context is closed");
    }
    a.put("engine", handle);
    return wasm.invoke(op, a);
  }

  private static Map<String, Object> args(String key, Object value) {
    Map<String, Object> a = new HashMap<>();
    a.put(key, value);
    return a;
  }
}
