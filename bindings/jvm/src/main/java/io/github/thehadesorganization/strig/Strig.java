package io.github.thehadesorganization.strig;

import com.fasterxml.jackson.core.type.TypeReference;
import java.util.HashMap;
import java.util.Map;

/** The policy language: compile and format text without an engine. */
public final class Strig {
  private static Engine shared;

  private Strig() {}

  private static synchronized Engine dsl() {
    if (shared == null) {
      shared = new Engine(Map.of("catalog", Map.of("targetKinds", java.util.List.of(), "broadTargets", java.util.List.of(), "permissions", java.util.List.of())));
    }
    return shared;
  }

  /**
   * Policy-language text to the policy JSON. A syntax error is {@code DSL_PARSE} and an invalid
   * policy {@code DSL_VALIDATE}; both carry {@link StrigException#diagnostics()}.
   */
  public static Map<String, Object> compile(String text) {
    return compile(text, null);
  }

  public static Map<String, Object> compile(String text, String file) {
    Map<String, Object> a = new HashMap<>();
    a.put("text", text);
    if (file != null) {
      a.put("options", Map.of("file", file));
    }
    return Wasm.JSON.convertValue(dsl().call("dsl.compile", a), new TypeReference<Map<String, Object>>() {});
  }

  /** Text in the canonical layout. */
  public static String format(String text) {
    Map<String, Object> a = new HashMap<>();
    a.put("text", text);
    return dsl().call("dsl.format", a).asText();
  }
}
