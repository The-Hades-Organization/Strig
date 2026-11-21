//! Janela gpui: avaliação com rastro, matriz de acesso com simulação e leitura da auditoria.
//!
//! Os arquivos são relidos sozinhos quando mudam no disco, então dá para editar o cenário no
//! editor de sempre e ver a decisão mudar.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use gpui::{
    App, AppContext, Bounds, ClickEvent, Context, Div, FontWeight, Hsla, InteractiveElement, IntoElement,
    ParentElement, Render, SharedString, StatefulInteractiveElement, Styled, Window, WindowBounds, WindowOptions, div,
    px, size,
};
use gpui_component::{ActiveTheme, Root};
use themis::{AuditRecord, ConditionTrace, Effect, Explanation, TraceResult};

use crate::inspector::Inspector;
use crate::render;
use crate::scenario::Scenario;
use crate::trail::{ChainStatus, Trail};

pub fn run(scenario: Option<PathBuf>, audit: Option<PathBuf>) {
    gpui_platform::application().run(move |cx: &mut App| {
        gpui_component::init(cx);
        let bounds = Bounds::centered(None, size(px(1320.0), px(840.0)), cx);
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            window_min_size: Some(size(px(900.0), px(560.0))),
            ..Default::default()
        };
        let opened = cx.open_window(options, move |window, cx| {
            window.set_window_title("Themis Inspect");
            let view = cx.new(|cx| InspectView::new(scenario, audit, cx));
            cx.new(|cx| Root::new(view, window, cx))
        });
        if let Err(error) = opened {
            eprintln!("themis-inspect: {error}");
            cx.quit();
        }
        cx.activate(true);
    });
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Evaluate,
    Matrix,
    Audit,
}

#[derive(Clone, Copy)]
struct Palette {
    fg: Hsla,
    muted: Hsla,
    border: Hsla,
    panel: Hsla,
    active: Hsla,
    allow: Hsla,
    deny: Hsla,
    warn: Hsla,
}

impl Palette {
    fn of(cx: &App) -> Self {
        let t = cx.theme();
        Self {
            fg: t.foreground,
            muted: t.muted_foreground,
            border: t.border,
            panel: t.sidebar,
            active: t.list_active,
            allow: t.success,
            deny: t.danger,
            warn: t.warning,
        }
    }

    fn effect(&self, effect: Effect) -> Hsla {
        match effect {
            Effect::Allow => self.allow,
            Effect::Deny => self.deny,
        }
    }
}

fn text(s: impl Into<SharedString>) -> SharedString {
    s.into()
}

fn mtime(path: &Option<PathBuf>) -> Option<SystemTime> {
    path.as_ref()
        .and_then(|p| std::fs::metadata(p).ok())
        .and_then(|m| m.modified().ok())
}

pub struct InspectView {
    scenario_path: Option<PathBuf>,
    audit_path: Option<PathBuf>,
    inspector: Option<Inspector>,
    trail: Option<Trail>,
    errors: Vec<String>,
    stamps: (Option<SystemTime>, Option<SystemTime>),
    tab: Tab,
    subject: usize,
    permission: usize,
    resource: usize,
    record: usize,
}

impl InspectView {
    fn new(scenario_path: Option<PathBuf>, audit_path: Option<PathBuf>, cx: &mut Context<Self>) -> Self {
        let mut view = Self {
            scenario_path,
            audit_path,
            inspector: None,
            trail: None,
            errors: Vec::new(),
            stamps: (None, None),
            tab: Tab::Evaluate,
            subject: 0,
            permission: 0,
            resource: 0,
            record: 0,
        };
        view.reload();
        if view.inspector.is_none() && view.trail.is_some() {
            view.tab = Tab::Audit;
        }
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                if this.update(cx, |view, cx| view.poll(cx)).is_err() {
                    break;
                }
            }
        })
        .detach();
        view
    }

    fn reload(&mut self) {
        self.errors.clear();
        if let Some(path) = &self.scenario_path {
            let loaded = Scenario::load(path).and_then(|scenario| match self.inspector.as_mut() {
                Some(inspector) => inspector.replace(scenario),
                None => Inspector::new(scenario).map(|i| self.inspector = Some(i)),
            });
            if let Err(error) = loaded {
                self.errors.push(error.to_string());
            }
        }
        if let Some(path) = &self.audit_path {
            match Trail::load(path) {
                Ok(trail) => self.trail = Some(trail),
                Err(error) => self.errors.push(error.to_string()),
            }
        }
        self.stamps = (mtime(&self.scenario_path), mtime(&self.audit_path));
    }

    fn poll(&mut self, cx: &mut Context<Self>) {
        if (mtime(&self.scenario_path), mtime(&self.audit_path)) != self.stamps {
            self.reload();
            cx.notify();
        }
    }

    fn names(&self) -> (Vec<String>, Vec<String>, Vec<String>) {
        match &self.inspector {
            Some(i) => (
                i.scenario().subjects.keys().cloned().collect(),
                i.permissions(),
                i.scenario().resources.keys().cloned().collect(),
            ),
            None => Default::default(),
        }
    }

    fn current(&self) -> Option<(Explanation, Explanation)> {
        let inspector = self.inspector.as_ref()?;
        let (subjects, permissions, resources) = self.names();
        let subject = inspector.subject(subjects.get(self.subject)?).ok()?;
        let resource = inspector.resource(resources.get(self.resource)?).ok()?;
        let permission = permissions.get(self.permission)?;
        Some((
            inspector.explain(subject, permission, resource),
            inspector.explain_baseline(subject, permission, resource),
        ))
    }

    // Partes da tela

    fn header(&self, p: Palette, cx: &mut Context<Self>) -> Div {
        let tab = |id: &'static str, label: &'static str, tab: Tab, cx: &mut Context<Self>| {
            let selected = self.tab == tab;
            div()
                .id(id)
                .px_3()
                .py_1()
                .rounded_md()
                .cursor_pointer()
                .when_selected(selected, p.active)
                .text_color(if selected { p.fg } else { p.muted })
                .child(label)
                .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                    this.tab = tab;
                    cx.notify();
                }))
        };
        let simulating = self.inspector.as_ref().is_some_and(Inspector::is_simulating);
        let files: Vec<String> = [&self.scenario_path, &self.audit_path]
            .into_iter()
            .flatten()
            .map(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .collect();
        div()
            .flex()
            .items_center()
            .gap_2()
            .px_3()
            .py_2()
            .border_b_1()
            .border_color(p.border)
            .child(
                div()
                    .font_weight(FontWeight::BOLD)
                    .text_color(p.fg)
                    .child("Themis Inspect"),
            )
            .child(div().text_sm().text_color(p.muted).child(text(files.join(" · "))))
            .child(div().flex_1())
            .child(tab("tab-eval", "Avaliação", Tab::Evaluate, cx))
            .child(tab("tab-matrix", "Matriz", Tab::Matrix, cx))
            .child(tab("tab-audit", "Auditoria", Tab::Audit, cx))
            .when_some_child(simulating.then(|| {
                div()
                    .id("reset")
                    .px_3()
                    .py_1()
                    .rounded_md()
                    .cursor_pointer()
                    .border_1()
                    .border_color(p.warn)
                    .text_color(p.warn)
                    .child("Desfazer simulação")
                    .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                        if let Some(i) = this.inspector.as_mut() {
                            i.reset();
                        }
                        cx.notify();
                    }))
            }))
            .child(
                div()
                    .id("reload")
                    .px_3()
                    .py_1()
                    .rounded_md()
                    .cursor_pointer()
                    .border_1()
                    .border_color(p.border)
                    .text_color(p.fg)
                    .child("Recarregar")
                    .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                        this.reload();
                        cx.notify();
                    })),
            )
    }

    fn picker(
        &self,
        p: Palette,
        title: &'static str,
        items: &[String],
        selected: usize,
        pick: fn(&mut Self, usize),
        cx: &mut Context<Self>,
    ) -> Div {
        div()
            .flex()
            .flex_col()
            .gap_1()
            .child(section_title(p, title))
            .children(items.iter().enumerate().map(|(i, name)| {
                div()
                    .id((title, i))
                    .px_2()
                    .py_0p5()
                    .rounded_md()
                    .cursor_pointer()
                    .text_sm()
                    .text_color(p.fg)
                    .when_selected(i == selected, p.active)
                    .child(text(name.clone()))
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        pick(this, i);
                        cx.notify();
                    }))
            }))
    }

    fn grant_toggles(&self, p: Palette, cx: &mut Context<Self>) -> Div {
        let Some(inspector) = &self.inspector else {
            return div();
        };
        let rows = inspector.scenario().grants.iter().enumerate().map(|(i, grant)| {
            let on = inspector.is_enabled(&grant.id);
            let id = grant.id.clone();
            div()
                .id(("grant", i))
                .flex()
                .gap_2()
                .px_2()
                .py_0p5()
                .rounded_md()
                .cursor_pointer()
                .text_sm()
                .text_color(if on { p.fg } else { p.muted })
                .child(if on { "☑" } else { "☐" })
                .child(
                    div()
                        .text_color(p.effect(grant.effect))
                        .child(if grant.effect == Effect::Allow { "allow" } else { "deny" }),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .child(text(format!("{} · {}", grant.id, grant.permission))),
                )
                .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                    if let Some(i) = this.inspector.as_mut() {
                        i.toggle(&id);
                    }
                    cx.notify();
                }))
        });
        let added = inspector.added().iter().map(|grant| {
            div()
                .px_2()
                .text_sm()
                .text_color(p.warn)
                .child(text(format!("+ {} · {} (simulado)", grant.id, grant.permission)))
        });
        div()
            .flex()
            .flex_col()
            .gap_1()
            .child(section_title(p, "Grants (clique para ligar/desligar)"))
            .children(rows)
            .children(added)
    }

    fn evaluate_tab(&self, p: Palette, cx: &mut Context<Self>) -> Div {
        let (subjects, permissions, resources) = self.names();
        let sidebar = div()
            .id("eval-sidebar")
            .w(px(340.0))
            .h_full()
            .flex()
            .flex_col()
            .gap_3()
            .p_3()
            .bg(p.panel)
            .border_r_1()
            .border_color(p.border)
            .overflow_y_scroll()
            .child(self.picker(p, "Sujeito", &subjects, self.subject, |v, i| v.subject = i, cx))
            .child(self.picker(
                p,
                "Permissão",
                &permissions,
                self.permission,
                |v, i| v.permission = i,
                cx,
            ))
            .child(self.picker(p, "Recurso", &resources, self.resource, |v, i| v.resource = i, cx))
            .child(self.grant_toggles(p, cx));
        let body = match self.current() {
            Some((now, baseline)) => {
                let simulated = self.inspector.as_ref().is_some_and(Inspector::is_simulating);
                explanation_panel(p, &now, simulated.then_some(&baseline))
            }
            None => empty(p, "Abra um cenário com --scenario para avaliar."),
        };
        div()
            .flex()
            .flex_1()
            .min_h(px(0.0))
            .child(sidebar)
            .child(div().id("eval-body").flex_1().h_full().overflow_y_scroll().child(body))
    }

    fn matrix_tab(&self, p: Palette, cx: &mut Context<Self>) -> Div {
        let (_, _, resources) = self.names();
        let Some(inspector) = &self.inspector else {
            return empty(p, "Abra um cenário com --scenario para ver a matriz.");
        };
        let Some(matrix) = resources.get(self.resource).and_then(|r| inspector.matrix(r).ok()) else {
            return empty(p, "O cenário não declara recursos.");
        };
        let chooser = div()
            .flex()
            .flex_wrap()
            .gap_1()
            .children(resources.iter().enumerate().map(|(i, name)| {
                div()
                    .id(("matrix-resource", i))
                    .px_2()
                    .py_0p5()
                    .rounded_md()
                    .cursor_pointer()
                    .text_sm()
                    .text_color(p.fg)
                    .border_1()
                    .border_color(p.border)
                    .when_selected(i == self.resource, p.active)
                    .child(text(name.clone()))
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        this.resource = i;
                        cx.notify();
                    }))
            }));
        let cell_w = px(110.0);
        let header = div()
            .flex()
            .child(
                div()
                    .w(px(300.0))
                    .text_sm()
                    .text_color(p.muted)
                    .child("permissão \\ sujeito"),
            )
            .children(
                matrix
                    .subjects
                    .iter()
                    .map(|s| div().w(cell_w).text_sm().text_color(p.muted).child(text(s.clone()))),
            );
        let rows = matrix.permissions.iter().enumerate().map(|(pi, permission)| {
            div()
                .flex()
                .items_center()
                .border_b_1()
                .border_color(p.border)
                .child(
                    div()
                        .w(px(300.0))
                        .py_1()
                        .text_sm()
                        .text_color(p.fg)
                        .child(text(permission.clone())),
                )
                .children((0..matrix.subjects.len()).map(|si| {
                    let effect = matrix.cells[pi][si];
                    let changed = matrix.changed(pi, si);
                    let label = match (effect, changed) {
                        (Effect::Allow, false) => "sim",
                        (Effect::Deny, false) => "não",
                        (Effect::Allow, true) => "sim *",
                        (Effect::Deny, true) => "não *",
                    };
                    div()
                        .id(("cell", pi * 10_000 + si))
                        .w(cell_w)
                        .py_1()
                        .px_2()
                        .m_0p5()
                        .rounded_md()
                        .cursor_pointer()
                        .text_sm()
                        .bg(p.effect(effect).opacity(0.18))
                        .text_color(p.effect(effect))
                        .border_1()
                        .border_color(if changed { p.warn } else { p.effect(effect).opacity(0.0) })
                        .child(label)
                        .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                            this.subject = si;
                            this.permission = pi;
                            this.tab = Tab::Evaluate;
                            cx.notify();
                        }))
                }))
        });
        let note = if matrix.changes().is_empty() {
            "Clique numa célula para ver o rastro."
        } else {
            "* mudou em relação aos grants originais. Clique numa célula para ver o rastro."
        };
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h(px(0.0))
            .p_3()
            .gap_3()
            .child(chooser)
            .child(
                div()
                    .id("matrix-body")
                    .flex_1()
                    .overflow_scroll()
                    .child(div().flex().flex_col().child(header).children(rows))
                    .child(div().pt_2().text_sm().text_color(p.muted).child(note)),
            )
    }

    fn audit_tab(&self, p: Palette, cx: &mut Context<Self>) -> Div {
        let Some(trail) = &self.trail else {
            return empty(p, "Abra uma trilha com --audit (JSON Lines gerado por JsonLinesAudit).");
        };
        let chain = trail.chain();
        let chain_color = match chain {
            ChainStatus::Broken(_) => p.deny,
            ChainStatus::Intact { .. } => p.allow,
            ChainStatus::Absent => p.muted,
        };
        let list = div()
            .id("audit-list")
            .w(px(460.0))
            .h_full()
            .flex()
            .flex_col()
            .gap_0p5()
            .p_2()
            .bg(p.panel)
            .border_r_1()
            .border_color(p.border)
            .overflow_y_scroll()
            .child(
                div()
                    .p_1()
                    .text_sm()
                    .text_color(chain_color)
                    .child(text(render::chain(&chain))),
            )
            .children(trail.records.iter().enumerate().map(|(i, record)| {
                div()
                    .id(("record", i))
                    .px_2()
                    .py_1()
                    .rounded_md()
                    .cursor_pointer()
                    .text_xs()
                    .text_color(outcome_color(p, record))
                    .when_selected(i == self.record, p.active)
                    .child(text(render::record_line(record)))
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        this.record = i;
                        cx.notify();
                    }))
            }));
        let detail = match trail.records.get(self.record) {
            Some(record) => self.record_detail(p, record),
            None => empty(p, "Trilha vazia."),
        };
        div().flex().flex_1().min_h(px(0.0)).child(list).child(
            div()
                .id("audit-body")
                .flex_1()
                .h_full()
                .overflow_y_scroll()
                .child(detail),
        )
    }

    fn record_detail(&self, p: Palette, record: &AuditRecord) -> Div {
        let json = serde_json::to_string_pretty(record).unwrap_or_default();
        let mut out = div().flex().flex_col().gap_3().p_3();
        if let Some(replay) = self.inspector.as_ref().and_then(|i| Trail::replay(record, i)) {
            out = out
                .child(section_title(p, "Reavaliação com a política e os grants atuais"))
                .child(
                    div()
                        .text_color(if replay.changed() { p.warn } else { p.allow })
                        .child(text(render::replay(&replay))),
                )
                .child(explanation_panel(p, &replay.now, None));
        }
        if let Some(explanation) = &record.explanation {
            out = out
                .child(section_title(p, "Rastro gravado na auditoria"))
                .child(explanation_panel(p, explanation, None));
        }
        out.child(section_title(p, "Registro")).child(
            div()
                .text_xs()
                .font_family("monospace")
                .text_color(p.fg)
                .child(text(json)),
        )
    }
}

fn outcome_color(p: Palette, record: &AuditRecord) -> Hsla {
    use themis::AuditOutcome::*;
    match record.outcome {
        Applied | Allowed => p.allow,
        Rejected | Denied => p.deny,
    }
}

trait Selected: Styled + Sized {
    fn when_selected(self, selected: bool, color: Hsla) -> Self {
        if selected { self.bg(color) } else { self }
    }
}

impl<T: Styled> Selected for T {}

trait OptionalChild: ParentElement + Sized {
    fn when_some_child(self, child: Option<impl IntoElement>) -> Self {
        match child {
            Some(child) => self.child(child),
            None => self,
        }
    }
}

impl<T: ParentElement> OptionalChild for T {}

fn section_title(p: Palette, title: &'static str) -> Div {
    div()
        .text_xs()
        .font_weight(FontWeight::BOLD)
        .text_color(p.muted)
        .child(title)
}

fn empty(p: Palette, message: &'static str) -> Div {
    div()
        .flex()
        .flex_1()
        .items_center()
        .justify_center()
        .p_6()
        .text_color(p.muted)
        .child(message)
}

fn chip(p: Palette, label: String, color: Hsla) -> Div {
    div()
        .px_2()
        .py_0p5()
        .rounded_md()
        .text_sm()
        .border_1()
        .border_color(color)
        .text_color(p.fg)
        .child(text(label))
}

fn condition_tree(p: Palette, node: &ConditionTrace, depth: usize) -> Div {
    let color = match node.result {
        TraceResult::True => p.allow,
        TraceResult::False => p.deny,
        TraceResult::Error(_) => p.warn,
        TraceResult::Skipped => p.muted,
    };
    let detail = match &node.result {
        TraceResult::Error(e) => format!("  ({e})"),
        _ => String::new(),
    };
    div()
        .flex()
        .flex_col()
        .child(
            div()
                .pl(px(16.0 * depth as f32))
                .text_sm()
                .font_family("monospace")
                .text_color(color)
                .child(text(format!(
                    "{} {}{}",
                    render::trace_mark(&node.result),
                    node.label,
                    detail
                ))),
        )
        .children(node.children.iter().map(|child| condition_tree(p, child, depth + 1)))
}

/// O rastro de uma decisão: veredito, caminho do recurso, overrides e o destino de cada grant.
fn explanation_panel(p: Palette, e: &Explanation, baseline: Option<&Explanation>) -> Div {
    let effect = e.decision.effect;
    let decisive = e.decisive();
    let decisive_rank = decisive.and_then(|g| g.rank);
    let subject = e.subject.id.clone().unwrap_or_else(|| e.subject.kind.clone());
    let banner = div()
        .flex()
        .flex_col()
        .gap_1()
        .p_3()
        .rounded_md()
        .bg(p.effect(effect).opacity(0.15))
        .border_1()
        .border_color(p.effect(effect))
        .child(
            div()
                .text_xl()
                .font_weight(FontWeight::BOLD)
                .text_color(p.effect(effect))
                .child(render::effect(effect)),
        )
        .child(
            div()
                .text_color(p.fg)
                .child(text(format!("{subject} pede {}", e.permission))),
        )
        .child(
            div()
                .text_sm()
                .text_color(p.fg)
                .child(text(render::reason(&e.decision.reason))),
        );
    let compare = baseline.filter(|b| b.decision.effect != effect).map(|b| {
        div().text_sm().text_color(p.warn).child(text(format!(
            "Com os grants originais: {} ({})",
            render::effect(b.decision.effect),
            render::reason(&b.decision.reason)
        )))
    });
    let path = div()
        .flex()
        .flex_wrap()
        .gap_1()
        .items_center()
        .children(e.path.iter().enumerate().map(|(rank, anchor)| {
            let color = if Some(rank) == decisive_rank {
                p.effect(effect)
            } else {
                p.border
            };
            chip(p, format!("{rank} · {anchor}"), color)
        }));
    let facts = div()
        .flex()
        .flex_col()
        .gap_1()
        .text_sm()
        .text_color(p.fg)
        .child(text(format!(
            "Papéis efetivos: {}",
            if e.roles.is_empty() {
                "nenhum".to_string()
            } else {
                e.roles.join(", ")
            }
        )))
        .child(text(format!("Permissões que concedem: {}", e.effective.join(", "))))
        .child(text(format!("Estratégia: {}", e.strategy)))
        .children(e.overrides.iter().map(|step| {
            text(format!(
                "Override {}: {}",
                step.name,
                render::override_outcome(step.outcome)
            ))
        }))
        .children(e.decision.warnings.iter().map(|w| text(format!("Aviso: {w}"))));
    let grants = e.grants.iter().map(|trace| {
        let is_decisive = decisive.is_some_and(|d| std::ptr::eq(d, trace));
        let accent = if trace.verdict.is_candidate() {
            p.effect(trace.grant.effect)
        } else {
            p.border
        };
        div()
            .flex()
            .flex_col()
            .gap_1()
            .p_2()
            .rounded_md()
            .border_1()
            .border_color(if is_decisive { p.effect(effect) } else { p.border })
            .border_l_4()
            .child(
                div()
                    .text_sm()
                    .text_color(if trace.verdict.is_candidate() { p.fg } else { p.muted })
                    .child(text(format!(
                        "{}{}",
                        if is_decisive { "★ " } else { "" },
                        render::grant_line(trace)
                    ))),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(accent)
                    .child(text(render::verdict(&trace.verdict))),
            )
            .when_some_child(trace.condition.as_ref().map(|c| condition_tree(p, c, 0)))
    });
    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_3()
        .child(banner)
        .when_some_child(compare)
        .child(section_title(p, "Caminho do recurso (degrau · âncora)"))
        .child(path)
        .child(facts)
        .child(section_title(p, "Grants entregues pela fonte"))
        .children(grants)
}

impl Render for InspectView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let p = Palette::of(cx);
        let body = match self.tab {
            Tab::Evaluate => self.evaluate_tab(p, cx),
            Tab::Matrix => self.matrix_tab(p, cx),
            Tab::Audit => self.audit_tab(p, cx),
        };
        let errors = self
            .errors
            .iter()
            .map(|e| div().px_3().py_1().text_sm().text_color(p.deny).child(text(e.clone())));
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(cx.theme().background)
            .text_color(p.fg)
            .child(self.header(p, cx))
            .children(errors)
            .child(body)
    }
}
