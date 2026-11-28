package io.github.thehadesorganization.strig;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** The grants, tuples, environment and instant of the decisions of one {@link Engine}. */
public final class Context implements AutoCloseable {
  private final Engine engine;
  private final long handle;
  private volatile boolean closed;

  Context(Engine engine, long handle) {
    this.engine = engine;
    this.handle = handle;
  }

  Engine engine() {
    return engine;
  }

  long handle() {
    return handle;
  }

  boolean isClosed() {
    return closed;
  }

  private com.fasterxml.jackson.databind.JsonNode op(String name, String key, Object value) {
    Map<String, Object> a = new HashMap<>();
    if (key != null) {
      a.put(key, value);
    }
    return engine.contextCall(name, this, a);
  }

  /** Replaces every grant. */
  public void setGrants(Object grants) {
    op("context.setGrants", "grants", grants);
  }

  /** Adds a grant, or replaces the one with the same id. */
  public void addGrant(Object grant) {
    op("context.addGrant", "grant", grant);
  }

  /** Removes a grant by id; whether it existed. */
  public boolean removeGrant(String id) {
    return op("context.removeGrant", "id", id).asBoolean();
  }

  public List<Map<String, Object>> grants() {
    return Wasm.JSON.convertValue(
        op("context.grants", null, null), new com.fasterxml.jackson.core.type.TypeReference<>() {});
  }

  /** Adds a relationship tuple; whether it was new. */
  public boolean addTuple(Object tuple) {
    return op("context.addTuple", "tuple", tuple).asBoolean();
  }

  /** Removes a relationship tuple; whether it existed. */
  public boolean removeTuple(Object tuple) {
    return op("context.removeTuple", "tuple", tuple).asBoolean();
  }

  public void setEnv(Object env) {
    op("context.setEnv", "env", env);
  }

  /** Fixes the instant of the context's decisions. */
  public void setNow(Instant now) {
    op("context.setNow", "now", now.toEpochMilli());
  }

  public void setLimits(Object limits) {
    op("context.setLimits", "limits", limits);
  }

  @Override
  public void close() {
    if (closed || engine.isClosed()) {
      return;
    }
    try {
      op("context.free", null, null);
    } finally {
      closed = true;
    }
  }
}
