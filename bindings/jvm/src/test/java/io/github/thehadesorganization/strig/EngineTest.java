package io.github.thehadesorganization.strig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

class EngineTest {
  static final Map<String, Object> SPEC =
      Map.of(
          "catalog",
          Map.of(
              "targetKinds", List.of("project"),
              "broadTargets", List.of("org"),
              "permissions",
                  List.of(
                      Map.of("key", "project.view", "targets", List.of("project")),
                      Map.of("key", "project.edit", "targets", List.of("project")))));

  static Map<String, Object> grant(String id, Map<String, Object> extra) {
    Map<String, Object> g = new HashMap<>();
    g.put("id", id);
    g.put("subject", Map.of("kind", "role", "id", "member"));
    g.put("permission", "project.view");
    g.put("target", Map.of("kind", "project"));
    g.put("effect", "allow");
    g.putAll(extra);
    return g;
  }

  static Map<String, Object> request(String permission, String project) {
    return Map.of(
        "subject", Map.of("kind", "user", "id", "ana", "roles", List.of(Map.of("role", "member"))),
        "permission", permission,
        "resource",
            Map.of("path", List.of(Map.of("kind", "project", "id", project), Map.of("kind", "org", "id", "o1"))));
  }

  @Test
  void checkDecideExplain() {
    try (Engine engine = new Engine(SPEC);
        Context ctx =
            engine.newContext(
                Map.of(
                    "grants",
                    List.of(
                        grant("v", Map.of()),
                        grant("d", Map.of("effect", "deny", "target", Map.of("kind", "project", "id", "p2"))))))) {
      assertTrue(engine.check(ctx, request("project.view", "p1")));
      assertFalse(engine.check(ctx, request("project.view", "p2")));
      assertFalse(engine.check(ctx, request("project.edit", "p1")));
      Decision decision = engine.decide(ctx, request("project.view", "p1"));
      assertTrue(decision.allowed());
      assertEquals("project.view", engine.explain(ctx, request("project.view", "p1")).get("permission"));
      assertEquals(
          List.of(true, false),
          engine.checkMany(ctx, List.of(request("project.view", "p1"), request("project.view", "p2"))));
    }
  }

  @Test
  void contextMutationShowsInTheNextDecision() {
    try (Engine engine = new Engine(SPEC);
        Context ctx = engine.newContext()) {
      assertFalse(engine.check(ctx, request("project.view", "p1")));
      ctx.addGrant(grant("v", Map.of()));
      assertTrue(engine.check(ctx, request("project.view", "p1")));
      assertTrue(ctx.removeGrant("v"));
      assertFalse(engine.check(ctx, request("project.view", "p1")));
    }
  }

  @Test
  void grantWindowFailsClosedWithoutNow() {
    Instant now = Instant.parse("2024-01-01T12:00:00Z");
    Map<String, Object> windowed = grant("w", Map.of("validUntil", now.plusSeconds(3600).toEpochMilli()));
    try (Engine engine = new Engine(SPEC);
        Context ctx = engine.newContext(Map.of("grants", List.of(windowed)))) {
      assertFalse(engine.check(ctx, request("project.view", "p1")));
      assertTrue(engine.check(ctx, request("project.view", "p1"), now));
      assertFalse(engine.check(ctx, request("project.view", "p1"), now.plusSeconds(7200)));
    }
  }

  @Test
  void errorsCarryTheStableCode() {
    try (Engine engine = new Engine(SPEC);
        Context ctx = engine.newContext()) {
      StrigException e = assertThrows(StrigException.class, () -> engine.check(ctx, Map.of("permission", 3)));
      assertEquals("INVALID_INPUT", e.code());
      assertEquals(
          "INVALID_INPUT", assertThrows(StrigException.class, () -> new Engine(Map.of("bogus", 1))).code());
    }
  }

  @Test
  void closedAndForeignHandlesAreRefused() {
    Engine a = new Engine(SPEC);
    Engine b = new Engine(SPEC);
    Context ctx = a.newContext();
    assertEquals(
        "INVALID_ARGUMENT",
        assertThrows(StrigException.class, () -> b.check(ctx, request("project.view", "p1"))).code());
    ctx.close();
    assertThrows(StrigException.class, () -> a.check(ctx, request("project.view", "p1")));
    a.close();
    assertThrows(StrigException.class, () -> a.check(ctx, request("project.view", "p1")));
    b.close();
  }

  @Test
  void listAndWhoCan() {
    try (Engine engine = new Engine(SPEC);
        Context ctx = engine.newContext(Map.of("grants", List.of(grant("v", Map.of()))))) {
      Map<String, Object> out =
          engine.list(ctx, request("x", "p1").get("subject"), "project.view", "project", null);
      assertEquals("project", out.get("kind"));
      assertFalse(engine.whoCan(ctx, "project.view").isEmpty());
      assertNotNull(engine.catalog());
    }
  }

  @Test
  void applyFillsTheHostClock() {
    try (Engine engine = new Engine(SPEC)) {
      StrigException e = assertThrows(StrigException.class, () -> engine.apply(Map.of()));
      assertEquals("INVALID_INPUT", e.code());
    }
  }

  @Test
  void compileAndFormat() {
    String text = "language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n}\n";
    assertNotNull(Strig.compile(text));
    assertEquals(text, Strig.format(text));
    StrigException e = assertThrows(StrigException.class, () -> Strig.compile("language blocks\n\npermission {"));
    assertEquals("DSL_PARSE", e.code());
    assertFalse(e.diagnostics().isEmpty());
  }

  @Test
  void concurrentUseAndFork() throws Exception {
    ExecutorService pool = Executors.newFixedThreadPool(8);
    try (Engine engine = new Engine(SPEC);
        Context ctx = engine.newContext(Map.of("grants", List.of(grant("v", Map.of()))))) {
      List<Future<Boolean>> results = new ArrayList<>();
      for (int i = 0; i < 8; i++) {
        results.add(pool.submit(() -> engine.check(ctx, request("project.view", "p1"))));
        results.add(
            pool.submit(
                () -> {
                  try (Engine fork = engine.fork();
                      Context own = fork.newContext(Map.of("grants", List.of(grant("v", Map.of()))))) {
                    return fork.check(own, request("project.view", "p1"));
                  }
                }));
      }
      for (Future<Boolean> f : results) {
        assertTrue(f.get());
      }
    } finally {
      pool.shutdown();
    }
  }
}
