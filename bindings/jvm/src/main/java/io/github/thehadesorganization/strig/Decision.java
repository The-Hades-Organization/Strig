package io.github.thehadesorganization.strig;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/** The answer of {@link Engine#decide}: an effect, the reason and what matched. */
public record Decision(String effect, JsonNode reason, List<String> matched, List<String> warnings) {
  public boolean allowed() {
    return "allow".equals(effect);
  }
}
