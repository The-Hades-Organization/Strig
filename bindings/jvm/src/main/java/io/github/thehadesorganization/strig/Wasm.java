package io.github.thehadesorganization.strig;

import com.dylibso.chicory.runtime.ExportFunction;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.wasm.Parser;
import com.dylibso.chicory.wasm.WasmModule;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** One instance of the engine module and the C ABI of {@code strig_call}. Not thread-safe. */
final class Wasm implements AutoCloseable {
  static final ObjectMapper JSON = new ObjectMapper();

  private static final class Holder {
    static final WasmModule MODULE = load();

    private static WasmModule load() {
      try (InputStream in = Wasm.class.getResourceAsStream("/strig.wasm")) {
        if (in == null) {
          throw new IllegalStateException("strig.wasm is missing from the class path; run scripts/build-wasi.sh");
        }
        return Parser.parse(in);
      } catch (IOException e) {
        throw new IllegalStateException("cannot read strig.wasm", e);
      }
    }
  }

  private final Instance instance;
  private final ExportFunction alloc;
  private final ExportFunction free;
  private final ExportFunction call;
  private boolean broken;

  Wasm() {
    this.instance = Instance.builder(Holder.MODULE).build();
    this.alloc = instance.export("strig_alloc");
    this.free = instance.export("strig_free");
    this.call = instance.export("strig_call");
  }

  /** Runs {@code op} and returns the {@code value} of the envelope, or throws {@link StrigException}. */
  JsonNode invoke(String op, Map<String, Object> args) {
    if (broken) {
      throw new StrigException("INTERNAL", "the engine instance trapped and was discarded");
    }
    byte[] opBytes = op.getBytes(StandardCharsets.UTF_8);
    byte[] body;
    try {
      body = JSON.writeValueAsBytes(args);
    } catch (IOException e) {
      throw new StrigException("INVALID_ARGUMENT", "argument is not JSON: " + e.getMessage());
    }
    JsonNode envelope;
    try {
      envelope = JSON.readTree(roundTrip(opBytes, body));
    } catch (IOException e) {
      throw new StrigException("INTERNAL", "unreadable answer: " + e.getMessage());
    }
    if (!envelope.path("ok").asBoolean(false)) {
      List<Object> diagnostics = new ArrayList<>();
      for (JsonNode d : envelope.path("diagnostics")) {
        diagnostics.add(JSON.convertValue(d, Object.class));
      }
      throw new StrigException(envelope.path("code").asText("INTERNAL"), envelope.path("message").asText(), diagnostics);
    }
    return envelope.path("value");
  }

  private byte[] roundTrip(byte[] op, byte[] body) {
    int opPtr = 0;
    int inPtr = 0;
    try {
      opPtr = put(op);
      inPtr = put(body);
      long packed = call.apply(opPtr, op.length, inPtr, body.length)[0];
      int ptr = (int) (packed >>> 32);
      int len = (int) packed;
      byte[] answer = instance.memory().readBytes(ptr, len);
      free.apply(ptr, len);
      return answer;
    } catch (RuntimeException e) {
      broken = true;
      throw new StrigException("INTERNAL", "the engine instance trapped and was discarded");
    } finally {
      if (!broken) {
        free.apply(opPtr, op.length);
        free.apply(inPtr, body.length);
      }
    }
  }

  private int put(byte[] data) {
    int ptr = (int) alloc.apply(data.length)[0];
    instance.memory().write(ptr, data);
    return ptr;
  }

  @Override
  public void close() {
    broken = true;
  }
}
