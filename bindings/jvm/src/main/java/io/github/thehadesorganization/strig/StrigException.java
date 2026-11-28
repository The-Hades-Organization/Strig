package io.github.thehadesorganization.strig;

import java.util.List;

/**
 * A failure reported by the engine. {@link #code()} is the stable {@code errorCode} of the
 * JavaScript binding ({@code INVALID_INPUT}, {@code UNKNOWN_SUBJECT}, {@code DSL_PARSE}, ...).
 */
public class StrigException extends RuntimeException {
  private final String code;
  private final transient List<Object> diagnostics;

  public StrigException(String code, String message) {
    this(code, message, List.of());
  }

  public StrigException(String code, String message, List<Object> diagnostics) {
    super(code + ": " + message);
    this.code = code;
    this.diagnostics = diagnostics == null ? List.of() : diagnostics;
  }

  /** The stable machine-readable code. */
  public String code() {
    return code;
  }

  /** Syntax and validation diagnostics of a policy-language failure; empty otherwise. */
  public List<Object> diagnostics() {
    return diagnostics;
  }
}
