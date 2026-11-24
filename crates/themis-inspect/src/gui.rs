//! Janela gpui: avaliação com rastro, matriz de acesso com simulação e leitura da auditoria.
//!
//! Os arquivos são relidos sozinhos quando mudam no disco, então dá para editar o cenário no
//! editor de sempre e ver a decisão mudar.

use std::borrow::Cow;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use gpui::prelude::FluentBuilder;
use gpui::{
    AnyElement, App, AppContext, AssetSource, Bounds, ClickEvent, Context, Div, FocusHandle, FontWeight,
    HighlightStyle, Hsla, InteractiveElement, IntoElement, KeyBinding, ParentElement, Render, SharedString,
    StatefulInteractiveElement, Styled, StyledText, Svg, Window, WindowAppearance, WindowBounds, WindowOptions,
    actions, div, px, rgb, size, svg,
};
use gpui_component::Root;
use gpui_component::scroll::ScrollableElement;
use themis::{
    AuditAction, AuditOutcome, AuditRecord, ConditionTrace, Effect, Explanation, Grant, GrantTrace, Reason,
    TraceResult, Verdict,
};

use crate::inspector::{Inspector, Matrix};
use crate::render;
use crate::scenario::Scenario;
use crate::trail::{ChainStatus, Replay, Trail};

const SANS: &str = "Noto Sans";
const MONO: &str = "JetBrains Mono";
const KEY_CONTEXT: &str = "ThemisInspect";

actions!(
    themis_inspect,
    [
        MoveUp,
        MoveDown,
        NextList,
        PrevList,
        Toggle,
        ShowEvaluate,
        ShowMatrix,
        ShowAudit,
        Reload,
        Undo
    ]
);

/// O que a janela mostra ao abrir: seleção, grants desligados e aba.
#[derive(Default)]
pub struct Start {
    pub subject: Option<String>,
    pub permission: Option<String>,
    pub resource: Option<String>,
    pub disable: Vec<String>,
    pub tab: Option<Tab>,
}

pub fn run(scenario: Option<PathBuf>, audit: Option<PathBuf>, start: Start) {
    gpui_platform::application()
        .with_assets(Assets)
        .run(move |cx: &mut App| {
            gpui_component::init(cx);
            load_fonts(cx);
            style_scrollbars(cx, tokens(false));
            bind_keys(cx);
            let bounds = Bounds::centered(None, size(px(1360.0), px(860.0)), cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(980.0), px(600.0))),
                ..Default::default()
            };
            let opened = cx.open_window(options, move |window, cx| {
                window.set_window_title("Themis Inspect");
                style_scrollbars(cx, tokens(is_dark(window)));
                window
                    .observe_window_appearance(|window, cx| {
                        style_scrollbars(cx, tokens(is_dark(window)));
                        window.refresh();
                    })
                    .detach();
                let view = cx.new(|cx| InspectView::new(scenario, audit, start, cx));
                let focus = view.read(cx).focus.clone();
                window.focus(&focus, cx);
                cx.new(|cx| Root::new(view, window, cx))
            });
            if let Err(error) = opened {
                eprintln!("themis-inspect: {error}");
                cx.quit();
            }
            cx.activate(true);
        });
}

fn load_fonts(cx: &mut App) {
    let fonts = vec![
        Cow::Borrowed(include_bytes!("../assets/fonts/NotoSans-Regular.ttf").as_slice()),
        Cow::Borrowed(include_bytes!("../assets/fonts/NotoSans-Medium.ttf").as_slice()),
        Cow::Borrowed(include_bytes!("../assets/fonts/NotoSans-SemiBold.ttf").as_slice()),
        Cow::Borrowed(include_bytes!("../assets/fonts/NotoSans-Italic.ttf").as_slice()),
        Cow::Borrowed(include_bytes!("../assets/fonts/JetBrainsMono-Regular.ttf").as_slice()),
        Cow::Borrowed(include_bytes!("../assets/fonts/JetBrainsMono-SemiBold.ttf").as_slice()),
    ];
    if let Err(error) = cx.text_system().add_fonts(fonts) {
        eprintln!("themis-inspect: fontes embutidas indisponíveis: {error}");
    }
}

/// A janela segue a aparência do sistema e troca quando ela muda.
fn is_dark(window: &Window) -> bool {
    matches!(
        window.appearance(),
        WindowAppearance::Dark | WindowAppearance::VibrantDark
    )
}

/// Barras finas na cor da borda, como as do playground.
fn style_scrollbars(cx: &mut App, t: Tokens) {
    let theme = gpui_component::Theme::global_mut(cx);
    theme.scrollbar = gpui::transparent_black();
    theme.scrollbar_thumb = t.line_strong;
    theme.scrollbar_thumb_hover = t.mute;
    gpui_component::Theme::set_scrollbar_mode(gpui_component::scroll::ScrollbarMode::Always, cx);
}

fn bind_keys(cx: &mut App) {
    let at = Some(KEY_CONTEXT);
    let [one, two, three, reload, undo] = if cfg!(target_os = "macos") {
        ["cmd-1", "cmd-2", "cmd-3", "cmd-r", "cmd-z"]
    } else {
        ["ctrl-1", "ctrl-2", "ctrl-3", "ctrl-r", "ctrl-z"]
    };
    cx.bind_keys([
        KeyBinding::new("up", MoveUp, at),
        KeyBinding::new("down", MoveDown, at),
        KeyBinding::new("tab", NextList, at),
        KeyBinding::new("shift-tab", PrevList, at),
        KeyBinding::new("space", Toggle, at),
        KeyBinding::new(one, ShowEvaluate, at),
        KeyBinding::new(two, ShowMatrix, at),
        KeyBinding::new(three, ShowAudit, at),
        KeyBinding::new(reload, Reload, at),
        KeyBinding::new(undo, Undo, at),
    ]);
}

/// O modificador dos atalhos como a plataforma escreve: ⌘ no macOS, Ctrl+ no resto.
fn shortcut(key: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("⌘{key}")
    } else {
        format!("Ctrl+{key}")
    }
}

/// Ícones desenhados para o app, embutidos no binário.
struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> gpui::Result<Option<Cow<'static, [u8]>>> {
        let bytes: &'static [u8] = match path {
            "icons/alert.svg" => include_bytes!("../assets/icons/alert.svg"),
            "icons/arrow-right.svg" => include_bytes!("../assets/icons/arrow-right.svg"),
            "icons/check.svg" => include_bytes!("../assets/icons/check.svg"),
            "icons/chevron-down.svg" => include_bytes!("../assets/icons/chevron-down.svg"),
            "icons/dot.svg" => include_bytes!("../assets/icons/dot.svg"),
            "icons/file.svg" => include_bytes!("../assets/icons/file.svg"),
            "icons/grid.svg" => include_bytes!("../assets/icons/grid.svg"),
            "icons/info.svg" => include_bytes!("../assets/icons/info.svg"),
            "icons/link.svg" => include_bytes!("../assets/icons/link.svg"),
            "icons/list.svg" => include_bytes!("../assets/icons/list.svg"),
            "icons/refresh.svg" => include_bytes!("../assets/icons/refresh.svg"),
            "icons/seal-allow.svg" => include_bytes!("../assets/icons/seal-allow.svg"),
            "icons/seal-cross.svg" => include_bytes!("../assets/icons/seal-cross.svg"),
            "icons/seal-deny.svg" => include_bytes!("../assets/icons/seal-deny.svg"),
            "icons/seal-knot.svg" => include_bytes!("../assets/icons/seal-knot.svg"),
            "icons/scale.svg" => include_bytes!("../assets/icons/scale.svg"),
            "icons/slash.svg" => include_bytes!("../assets/icons/slash.svg"),
            "icons/undo.svg" => include_bytes!("../assets/icons/undo.svg"),
            "icons/x.svg" => include_bytes!("../assets/icons/x.svg"),
            _ => return Ok(None),
        };
        Ok(Some(Cow::Borrowed(bytes)))
    }

    fn list(&self, _path: &str) -> gpui::Result<Vec<SharedString>> {
        Ok(Vec::new())
    }
}

/// Paleta da identidade do playground (`playground/IDENTITY.md`), nos dois temas.
///
/// Jade para estrutura, seleção e allow; argila para deny; `err` para defeito de texto;
/// `gold_ink` para quem, onde e números; `gold` só como ornamento e foco, nunca como texto.
#[derive(Clone, Copy)]
struct Tokens {
    bg: Hsla,
    panel: Hsla,
    sunk: Hsla,
    line: Hsla,
    line_strong: Hsla,
    ink: Hsla,
    mute: Hsla,
    comment: Hsla,
    jade: Hsla,
    jade_bg: Hsla,
    jade_soft: Hsla,
    jade_line: Hsla,
    gold: Hsla,
    gold_ink: Hsla,
    gold_bg: Hsla,
    gold_line: Hsla,
    deny: Hsla,
    deny_bg: Hsla,
    deny_line: Hsla,
    err: Hsla,
    err_bg: Hsla,
    err_line: Hsla,
}

type Tone = (Hsla, Hsla, Hsla);

/// Raios da identidade: 4 (código em linha), 8 (controles), 14 (cartões); a pílula é `rounded_full`.
const R1: f32 = 4.0;
const R2: f32 = 8.0;
const R3: f32 = 14.0;

/// Um tema: `[bg, panel, sunk, line, line-strong, ink, mute, comment, jade, jade-bg, gold, gold-ink,
/// gold-bg, deny, deny-bg, err]`, na ordem da tabela da identidade.
const LIGHT: [u32; 16] = [
    0xF1F0EB, 0xF8F7F3, 0xECEAE2, 0xDAD6CA, 0xBDB8A8, 0x16201D, 0x4E6B63, 0x496359, 0x1F5C51, 0xDAE8E1, 0xB07D1E,
    0x7A5410, 0xF0E3C2, 0x8E3226, 0xF3DED6, 0xB0301F,
];
const DARK: [u32; 16] = [
    0x16201D, 0x1B2824, 0x131B19, 0x26352F, 0x3A5047, 0xE9E2D0, 0x9FC0B2, 0x8DAA9F, 0x7CC3AE, 0x1F3A33, 0xE3B04B,
    0xE3B04B, 0x3A3118, 0xF0A08D, 0x3C2420, 0xF4906F,
];

fn hex(color: u32) -> Hsla {
    rgb(color).into()
}

/// Mistura `fg` com `bg`: `weight` é a parte de `fg`. Dá a borda de um tom a partir da cor e do fundo.
fn mix(fg: u32, bg: u32, weight: f32) -> Hsla {
    let channel = |shift: u32| {
        let a = ((fg >> shift) & 0xFF) as f32;
        let b = ((bg >> shift) & 0xFF) as f32;
        (a * weight + b * (1.0 - weight)).round() as u32
    };
    rgb((channel(16) << 16) | (channel(8) << 8) | channel(0)).into()
}

fn tokens(dark: bool) -> Tokens {
    let c = if dark { &DARK } else { &LIGHT };
    let [
        bg,
        panel,
        sunk,
        line,
        line_strong,
        ink,
        mute,
        comment,
        jade,
        jade_bg,
        gold,
        gold_ink,
        gold_bg,
        deny,
        deny_bg,
        err,
    ] = *c;
    Tokens {
        bg: hex(bg),
        panel: hex(panel),
        sunk: hex(sunk),
        line: hex(line),
        line_strong: hex(line_strong),
        ink: hex(ink),
        mute: hex(mute),
        comment: hex(comment),
        jade: hex(jade),
        jade_bg: hex(jade_bg),
        jade_soft: mix(jade_bg, panel, 0.45),
        jade_line: mix(jade, jade_bg, 0.45),
        gold: hex(gold),
        gold_ink: hex(gold_ink),
        gold_bg: hex(gold_bg),
        gold_line: mix(gold, gold_bg, 0.7),
        deny: hex(deny),
        deny_bg: hex(deny_bg),
        deny_line: mix(deny, deny_bg, 0.45),
        err: hex(err),
        err_bg: mix(err, panel, 0.1),
        err_line: mix(err, panel, 0.5),
    }
}

impl Tokens {
    fn effect(&self, effect: Effect) -> Tone {
        match effect {
            Effect::Allow => (self.jade, self.jade_bg, self.jade_line),
            Effect::Deny => (self.deny, self.deny_bg, self.deny_line),
        }
    }

    fn info(&self) -> Tone {
        (self.jade, self.jade_soft, self.jade_line)
    }

    fn caution(&self) -> Tone {
        (self.gold_ink, self.gold_bg, self.gold_line)
    }

    /// Defeito de texto ou de leitura: nunca divide forma nem cor com o deny.
    fn error(&self) -> Tone {
        (self.err, self.err_bg, self.err_line)
    }

    fn quiet(&self) -> Tone {
        (self.mute, self.panel, self.line)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Evaluate,
    Matrix,
    Audit,
}

/// A lista que recebe as setas do teclado na aba Avaliação.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Subject,
    Permission,
    Resource,
    Grants,
}

impl Field {
    const ORDER: [Field; 4] = [Field::Subject, Field::Permission, Field::Resource, Field::Grants];

    fn title(self) -> &'static str {
        match self {
            Field::Subject => "Sujeito",
            Field::Permission => "Permissão",
            Field::Resource => "Recurso",
            Field::Grants => "Grants",
        }
    }

    fn step(self, forward: bool) -> Field {
        let at = Field::ORDER.iter().position(|f| *f == self).unwrap_or(0);
        let len = Field::ORDER.len();
        Field::ORDER[if forward { (at + 1) % len } else { (at + len - 1) % len }]
    }
}

/// Rótulo em capitais espaçadas. O gpui não tem espaçamento entre letras, então cada letra
/// recebe um espaço fino depois (aproxima os 0.16 em do playground).
fn caps(s: &str) -> SharedString {
    let mut out = String::new();
    let mut letters = s.chars().peekable();
    while let Some(c) = letters.next() {
        if c == ' ' {
            out.push('\u{2002}');
            continue;
        }
        out.extend(c.to_uppercase());
        if letters.peek().is_some_and(|n| *n != ' ') {
            out.push('\u{200A}');
        }
    }
    out.into()
}

/// JSON com as cores de realce do playground: chaves em jade, textos em `mute`, números e booleanos
/// em `gold_ink`, e `allow`/`deny` na cor do efeito.
fn json_text(t: Tokens, json: String) -> StyledText {
    let paint = |color: Hsla, bold: bool| HighlightStyle {
        color: Some(color),
        font_weight: bold.then_some(FontWeight::BOLD),
        ..Default::default()
    };
    let mut marks = Vec::new();
    let bytes = json.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'"' => {
                let start = at;
                at += 1;
                while at < bytes.len() && bytes[at] != b'"' {
                    at += if bytes[at] == b'\\' { 2 } else { 1 };
                }
                at = (at + 1).min(bytes.len());
                let word = &json[start..at];
                let is_key = json[at..].trim_start_matches(' ').starts_with(':');
                let style = match word {
                    _ if is_key => paint(t.jade, true),
                    "\"allow\"" => paint(t.jade, true),
                    "\"deny\"" => paint(t.deny, true),
                    _ => paint(t.mute, false),
                };
                marks.push((start..at, style));
            }
            b'-' | b'0'..=b'9' | b't' | b'f' | b'n' => {
                let start = at;
                while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || matches!(bytes[at], b'-' | b'.' | b'+'))
                {
                    at += 1;
                }
                marks.push((start..at, paint(t.gold_ink, false)));
            }
            _ => at += 1,
        }
    }
    StyledText::new(json).with_highlights(marks)
}

fn text(s: impl Into<SharedString>) -> SharedString {
    s.into()
}

fn icon(name: &str, size: f32, color: Hsla) -> Svg {
    svg()
        .path(format!("icons/{name}.svg"))
        .size(px(size))
        .flex_none()
        .text_color(color)
}

fn mono(s: impl Into<SharedString>) -> Div {
    div().font_family(MONO).text_size(px(12.5)).child(s.into())
}

/// Mensagem de erro de leitura que sempre começa pelo nome do arquivo e diz o que fazer.
fn failure(path: &std::path::Path, error: &str, hint: &str) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let error = error.strip_prefix(&format!("{}: ", path.display())).unwrap_or(error);
    format!("{name}: {error}. {hint}")
}

fn mtime(path: &Option<PathBuf>) -> Option<SystemTime> {
    path.as_ref()
        .and_then(|p| std::fs::metadata(p).ok())
        .and_then(|m| m.modified().ok())
}

fn effect_text(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "permitido",
        Effect::Deny => "negado",
    }
}

/// Selo em pílula: ícone + rótulo, com borda e fundo do estado.
fn label(icon_name: Option<&str>, caption: impl Into<SharedString>, tone: Tone) -> Div {
    let (fg, bg, line) = tone;
    div()
        .flex()
        .flex_none()
        .items_center()
        .gap(px(4.0))
        .h(px(22.0))
        .px(px(8.0))
        .rounded_full()
        .border_1()
        .border_color(line)
        .bg(bg)
        .text_color(fg)
        .text_size(px(12.0))
        .font_weight(FontWeight::MEDIUM)
        .when_some(icon_name, |this, name| this.child(icon(name, 12.0, fg)))
        .child(caption.into())
}

/// O selo da decisão: a faixa a −9° aberta no allow, fechada e cruzada no deny, com o nó dourado.
/// A palavra do veredito vai ao lado, então a forma nunca depende só da cor.
fn seal(t: Tokens, effect: Effect, size: f32) -> Div {
    let (fg, _, _) = t.effect(effect);
    let fg_bg = t.effect(effect).1;
    let layer = |name: &str, color: Hsla| icon(name, size, color).absolute().top_0().left_0();
    div()
        .relative()
        .flex_none()
        .size(px(size))
        .child(layer(
            match effect {
                Effect::Allow => "seal-allow",
                Effect::Deny => "seal-deny",
            },
            fg,
        ))
        .child(layer("seal-knot", t.gold))
        .when(effect == Effect::Deny, |this| {
            this.child(
                icon("seal-cross", size * 0.34, fg_bg)
                    .absolute()
                    .top(px(size * 0.30))
                    .left(px(size * 0.30)),
            )
        })
}

fn effect_label(t: Tokens, effect: Effect) -> Div {
    match effect {
        Effect::Allow => label(Some("check"), "allow", t.effect(effect)),
        Effect::Deny => label(Some("x"), "deny", t.effect(effect)),
    }
}

/// Caixa com cabeçalho cinza.
fn boxed(t: Tokens, header: impl IntoElement, body: impl IntoElement) -> Div {
    div()
        .flex()
        .flex_col()
        .border_1()
        .border_color(t.line)
        .rounded(px(R3))
        .bg(t.panel)
        .overflow_hidden()
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(10.0))
                .min_h(px(44.0))
                .px(px(16.0))
                .bg(t.sunk)
                .border_b_1()
                .border_color(t.line)
                .child(header),
        )
        .child(body)
}

fn box_title(t: Tokens, title: &str, sub: Option<&str>) -> Div {
    div()
        .flex()
        .items_baseline()
        .gap(px(8.0))
        .child(
            div()
                .text_size(px(11.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(t.ink)
                .child(caps(title)),
        )
        .when_some(sub, |this, sub| {
            this.child(div().text_color(t.mute).child(text(sub.to_string())))
        })
}

fn button(t: Tokens, id: &'static str, icon_name: &str, caption: &'static str, tone: Tone) -> gpui::Stateful<Div> {
    let (fg, bg, line) = tone;
    div()
        .id(id)
        .flex()
        .flex_none()
        .items_center()
        .gap(px(8.0))
        .h(px(32.0))
        .px(px(12.0))
        .rounded(px(R2))
        .border_1()
        .border_color(line)
        .bg(bg)
        .text_color(fg)
        .font_weight(FontWeight::MEDIUM)
        .cursor_pointer()
        .hover(move |s| s.bg(t.sunk))
        .child(icon(icon_name, 16.0, if fg == t.ink { t.mute } else { fg }))
        .child(caption)
}

/// Dica de atalho de teclado.
fn kbd(t: Tokens, keys: impl Into<SharedString>) -> Div {
    div()
        .flex_none()
        .px(px(5.0))
        .rounded(px(R1))
        .border_1()
        .border_color(t.line)
        .bg(t.bg)
        .text_size(px(11.0))
        .text_color(t.mute)
        .font_family(MONO)
        .child(keys.into())
}

/// Por que a decisão saiu assim, quando um grant que teria permitido foi descartado.
struct Insight {
    lead: String,
    expression: Option<String>,
    rank: Option<usize>,
}

fn insight(e: &Explanation) -> Option<Insight> {
    if e.decision.effect == Effect::Allow {
        return None;
    }
    if let Reason::MissingPrerequisite {
        permission,
        prerequisite,
    } = &e.decision.reason
    {
        return Some(Insight {
            lead: format!(
                "os grants permitiriam {permission}, mas ela exige {prerequisite}, que não é permitida aqui."
            ),
            expression: None,
            rank: None,
        });
    }
    e.grants.iter().find_map(|trace| {
        if trace.grant.effect != Effect::Allow {
            return None;
        }
        let rank = trace.rank;
        let at = rank.map(|r| format!(" no degrau {r}")).unwrap_or_default();
        let id = &trace.grant.id;
        let (lead, expression) = match &trace.verdict {
            Verdict::ConditionFalse => {
                let leaf = trace.condition.as_ref().and_then(first_false_leaf);
                match leaf {
                    Some(leaf) => (
                        format!("{id} teria permitido{at}, mas a condição falhou:"),
                        Some(leaf.label.clone()),
                    ),
                    None => (format!("{id} teria permitido{at}, mas a condição falhou."), None),
                }
            }
            Verdict::ConditionUnresolved { problem } => (
                format!("{id} teria permitido{at}, mas a condição não pôde ser avaliada ({problem})."),
                None,
            ),
            Verdict::SubjectUnresolved { problem } => (
                format!("{id} teria permitido{at}, mas o sujeito não pôde ser avaliado ({problem})."),
                None,
            ),
            _ => return None,
        };
        Some(Insight { lead, expression, rank })
    })
}

fn first_false_leaf(node: &ConditionTrace) -> Option<&ConditionTrace> {
    if !matches!(node.result, TraceResult::False) {
        return None;
    }
    if node.children.is_empty() {
        return Some(node);
    }
    node.children.iter().find_map(first_false_leaf)
}

fn target_text(grant: &Grant) -> String {
    match &grant.target.id {
        Some(id) => format!("{}:{id}", grant.target.kind),
        None => grant.target.kind.clone(),
    }
}

/// Data UTC de um instante em milissegundos desde 1970.
fn timestamp(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// O estado da cadeia, com o nível como identificador.
fn chain_text(chain: &ChainStatus) -> Div {
    let level = || mono("forensic").whitespace_nowrap();
    match chain {
        ChainStatus::Intact { records } => div()
            .flex()
            .flex_wrap()
            .items_baseline()
            .gap_x(px(4.0))
            .child(text(format!(
                "Cadeia de hashes íntegra: {records} {} no nível",
                if *records == 1 { "registro" } else { "registros" }
            )))
            .child(level()),
        ChainStatus::Absent => div()
            .flex()
            .flex_wrap()
            .items_baseline()
            .gap_x(px(4.0))
            .child("Nenhum registro no nível")
            .child(level())
            .child(": não há cadeia de hashes para conferir."),
        ChainStatus::Broken(error) => div().child(text(format!("Cadeia de hashes quebrada: {error}"))),
    }
}

fn action_text(action: &AuditAction) -> &'static str {
    match action {
        AuditAction::GrantAdd => "grant adicionado",
        AuditAction::GrantRemove => "grant removido",
        AuditAction::TupleAdd => "relação adicionada",
        AuditAction::TupleRemove => "relação removida",
        AuditAction::RoleAssign => "papel atribuído",
        AuditAction::RoleRevoke => "papel revogado",
        AuditAction::Decision => "decisão",
        AuditAction::ExclusiveAcquire => "posse exclusiva adquirida",
        AuditAction::ExclusivePreempt => "posse exclusiva tomada",
        AuditAction::ExclusiveRelease => "posse exclusiva liberada",
        AuditAction::ExclusiveExpire => "posse exclusiva expirada",
    }
}

fn outcome_label(t: Tokens, outcome: &AuditOutcome) -> Div {
    match outcome {
        AuditOutcome::Applied => label(Some("check"), "aplicada", t.effect(Effect::Allow)),
        AuditOutcome::Rejected => label(Some("x"), "recusada", t.effect(Effect::Deny)),
        AuditOutcome::Allowed => label(Some("check"), "permitido", t.effect(Effect::Allow)),
        AuditOutcome::Denied => label(Some("x"), "negado", t.effect(Effect::Deny)),
    }
}

/// O que a simulação mudou, para mostrar os grants desligados no lugar deles.
struct Sim<'a> {
    baseline: &'a Explanation,
    grants: &'a [Grant],
    enabled: Vec<bool>,
}

pub struct InspectView {
    focus: FocusHandle,
    scenario_path: Option<PathBuf>,
    audit_path: Option<PathBuf>,
    inspector: Option<Inspector>,
    trail: Option<Trail>,
    errors: Vec<String>,
    stamps: (Option<SystemTime>, Option<SystemTime>),
    tab: Tab,
    list: Field,
    subject: usize,
    permission: usize,
    resource: usize,
    grant: usize,
    record: usize,
    ring: bool,
    keyboard: bool,
}

impl InspectView {
    fn new(scenario_path: Option<PathBuf>, audit_path: Option<PathBuf>, start: Start, cx: &mut Context<Self>) -> Self {
        let mut view = Self {
            focus: cx.focus_handle(),
            scenario_path,
            audit_path,
            inspector: None,
            trail: None,
            errors: Vec::new(),
            stamps: (None, None),
            tab: Tab::Evaluate,
            list: Field::Subject,
            subject: 0,
            permission: 0,
            resource: 0,
            grant: 0,
            record: 0,
            ring: false,
            keyboard: false,
        };
        view.reload();
        if view.inspector.is_none() && view.trail.is_some() {
            view.tab = Tab::Audit;
        }
        view.apply(start);
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

    fn apply(&mut self, start: Start) {
        let (subjects, permissions, resources) = self.names();
        let find =
            |names: &[String], wanted: &Option<String>| wanted.as_ref().and_then(|w| names.iter().position(|n| n == w));
        if let Some(i) = find(&subjects, &start.subject) {
            self.subject = i;
        }
        if let Some(i) = find(&permissions, &start.permission) {
            self.permission = i;
        }
        if let Some(i) = find(&resources, &start.resource) {
            self.resource = i;
        }
        if let Some(inspector) = self.inspector.as_mut() {
            for id in &start.disable {
                inspector.toggle(id);
            }
        }
        if let Some(tab) = start.tab {
            self.tab = tab;
        }
    }

    fn reload(&mut self) {
        self.errors.clear();
        let hint = "Corrija o arquivo e salve: o app recarrega sozinho.";
        if let Some(path) = &self.scenario_path {
            let loaded = Scenario::load(path).and_then(|scenario| match self.inspector.as_mut() {
                Some(inspector) => inspector.replace(scenario),
                None => Inspector::new(scenario).map(|i| self.inspector = Some(i)),
            });
            if let Err(error) = loaded {
                self.errors.push(failure(path, &error.to_string(), hint));
            }
        }
        if let Some(path) = &self.audit_path {
            match Trail::load(path) {
                Ok(trail) => self.trail = Some(trail),
                Err(error) => self.errors.push(failure(path, &error.to_string(), hint)),
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

    fn simulating(&self) -> bool {
        self.inspector.as_ref().is_some_and(Inspector::is_simulating)
    }

    fn selected(&self, field: Field) -> usize {
        match field {
            Field::Subject => self.subject,
            Field::Permission => self.permission,
            Field::Resource => self.resource,
            Field::Grants => self.grant,
        }
    }

    fn select(&mut self, field: Field, index: usize) {
        self.list = field;
        match field {
            Field::Subject => self.subject = index,
            Field::Permission => self.permission = index,
            Field::Resource => self.resource = index,
            Field::Grants => self.grant = index,
        }
    }

    // Teclado

    fn move_by(&mut self, delta: isize, cx: &mut Context<Self>) {
        self.keyboard = true;
        let (subjects, permissions, resources) = self.names();
        let step = |at: usize, len: usize| -> usize {
            if len == 0 {
                return 0;
            }
            (at as isize + delta).clamp(0, len as isize - 1) as usize
        };
        match self.tab {
            Tab::Evaluate => {
                let len = match self.list {
                    Field::Subject => subjects.len(),
                    Field::Permission => permissions.len(),
                    Field::Resource => resources.len(),
                    Field::Grants => self.inspector.as_ref().map_or(0, |i| i.scenario().grants.len()),
                };
                let at = step(self.selected(self.list), len);
                self.select(self.list, at);
            }
            Tab::Matrix => self.resource = step(self.resource, resources.len()),
            Tab::Audit => self.record = step(self.record, self.trail.as_ref().map_or(0, |t| t.records.len())),
        }
        cx.notify();
    }

    fn on_up(&mut self, _: &MoveUp, _: &mut Window, cx: &mut Context<Self>) {
        self.move_by(-1, cx);
    }

    fn on_down(&mut self, _: &MoveDown, _: &mut Window, cx: &mut Context<Self>) {
        self.move_by(1, cx);
    }

    fn on_next_list(&mut self, _: &NextList, _: &mut Window, cx: &mut Context<Self>) {
        self.keyboard = true;
        self.list = self.list.step(true);
        cx.notify();
    }

    fn on_prev_list(&mut self, _: &PrevList, _: &mut Window, cx: &mut Context<Self>) {
        self.keyboard = true;
        self.list = self.list.step(false);
        cx.notify();
    }

    fn on_toggle(&mut self, _: &Toggle, _: &mut Window, cx: &mut Context<Self>) {
        if self.tab != Tab::Evaluate || self.list != Field::Grants {
            return;
        }
        if let Some(inspector) = self.inspector.as_mut()
            && let Some(id) = inspector.scenario().grants.get(self.grant).map(|g| g.id.clone())
        {
            inspector.toggle(&id);
        }
        cx.notify();
    }

    fn show(&mut self, tab: Tab, cx: &mut Context<Self>) {
        self.tab = tab;
        cx.notify();
    }

    fn on_reload(&mut self, _: &Reload, _: &mut Window, cx: &mut Context<Self>) {
        self.reload();
        cx.notify();
    }

    fn on_undo(&mut self, _: &Undo, _: &mut Window, cx: &mut Context<Self>) {
        if let Some(i) = self.inspector.as_mut() {
            i.reset();
        }
        cx.notify();
    }

    /// Anel de foco na linha ativa da lista que recebe as setas.
    fn ring(&self, t: Tokens, on: bool) -> Hsla {
        if self.ring && on {
            t.jade
        } else {
            gpui::transparent_black()
        }
    }

    // Cabeçalho

    fn header(&self, t: Tokens, cx: &mut Context<Self>) -> Div {
        let tab = |id: &'static str, glyph: &'static str, caption: &'static str, tab: Tab, cx: &mut Context<Self>| {
            let on = self.tab == tab;
            div()
                .id(id)
                .relative()
                .flex()
                .items_center()
                .h_full()
                .px(px(10.0))
                .gap(px(8.0))
                .cursor_pointer()
                .child(icon(glyph, 16.0, t.mute))
                .child(
                    div()
                        .px(px(8.0))
                        .py(px(4.0))
                        .rounded(px(R2))
                        .text_color(if on { t.jade } else { t.mute })
                        .text_size(px(11.0))
                        .font_weight(FontWeight::SEMIBOLD)
                        .hover(move |s| s.bg(t.sunk))
                        .child(caps(caption)),
                )
                .when(on, |this| {
                    this.child(
                        div()
                            .absolute()
                            .left(px(8.0))
                            .right(px(8.0))
                            .bottom(px(-1.0))
                            .h(px(2.0))
                            .rounded(px(2.0))
                            .bg(t.gold),
                    )
                })
                .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| this.show(tab, cx)))
        };
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
            .flex_none()
            .items_center()
            .gap(px(16.0))
            .h(px(56.0))
            .px(px(24.0))
            .border_b_1()
            .border_color(t.line)
            .bg(t.bg)
            .child(
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .gap(px(8.0))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_center()
                            .size(px(28.0))
                            .rounded(px(R2))
                            .border_1()
                            .border_color(t.line)
                            .bg(t.panel)
                            .child(icon("scale", 16.0, t.ink)),
                    )
                    .child(
                        div()
                            .text_size(px(13.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(t.ink)
                            .child(caps("Themis Inspect")),
                    ),
            )
            .when(!files.is_empty(), |this| {
                this.child(
                    div()
                        .flex()
                        .min_w(px(0.0))
                        .items_center()
                        .gap(px(6.0))
                        .h(px(28.0))
                        .px(px(10.0))
                        .rounded_full()
                        .border_1()
                        .border_color(t.line)
                        .text_color(t.mute)
                        .child(icon("file", 14.0, t.mute))
                        .child(
                            mono(files.join(" · "))
                                .whitespace_nowrap()
                                .overflow_hidden()
                                .text_ellipsis(),
                        ),
                )
            })
            .child(
                div()
                    .flex()
                    .flex_none()
                    .h_full()
                    .ml(px(8.0))
                    .gap(px(4.0))
                    .child(tab("tab-eval", "scale", "Avaliação", Tab::Evaluate, cx))
                    .child(tab("tab-matrix", "grid", "Matriz", Tab::Matrix, cx))
                    .child(tab("tab-audit", "list", "Auditoria", Tab::Audit, cx)),
            )
            .child(div().flex_1())
            .when(self.simulating(), |this| {
                this.child(
                    button(t, "reset", "undo", "Desfazer simulação", t.caution())
                        .on_click(cx.listener(|this, _: &ClickEvent, window, cx| this.on_undo(&Undo, window, cx))),
                )
            })
            .child(
                button(t, "reload", "refresh", "Recarregar", (t.ink, t.panel, t.line))
                    .on_click(cx.listener(|this, _: &ClickEvent, window, cx| this.on_reload(&Reload, window, cx))),
            )
    }

    // Barra lateral

    fn picker(&self, t: Tokens, field: Field, items: &[String], cx: &mut Context<Self>) -> Div {
        let selected = self.selected(field);
        let active = self.list == field;
        div()
            .flex()
            .flex_col()
            .child(sidebar_title(t, field.title(), None, active))
            .children(items.iter().enumerate().map(|(i, name)| {
                let on = i == selected;
                div()
                    .id((field.title(), i))
                    .flex()
                    .items_center()
                    .gap(px(8.0))
                    .h(px(30.0))
                    .px(px(8.0))
                    .rounded(px(R2))
                    .border_2()
                    .border_color(self.ring(t, active && on))
                    .cursor_pointer()
                    .text_color(t.ink)
                    .hover(move |s| s.bg(t.sunk))
                    .when(on, |this| this.bg(t.jade_bg).font_weight(FontWeight::SEMIBOLD))
                    .child(if field == Field::Subject {
                        div().child(text(name.clone()))
                    } else {
                        mono(name.clone())
                    })
                    .when(on, |this| this.child(div().flex_1()).child(icon("check", 16.0, t.jade)))
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        this.select(field, i);
                        cx.notify();
                    }))
            }))
    }

    fn grant_toggles(&self, t: Tokens, cx: &mut Context<Self>) -> Div {
        let Some(inspector) = &self.inspector else {
            return div();
        };
        let active = self.list == Field::Grants;
        let rows = inspector.scenario().grants.iter().enumerate().map(|(i, grant)| {
            let on = inspector.is_enabled(&grant.id);
            let (fg, _, _) = t.effect(grant.effect);
            div()
                .id(("grant", i))
                .flex()
                .items_start()
                .gap(px(8.0))
                .py(px(4.0))
                .px(px(8.0))
                .rounded(px(R2))
                .border_2()
                .border_color(self.ring(t, active && i == self.grant))
                .cursor_pointer()
                .hover(move |s| s.bg(t.sunk))
                .child(checkbox(t, on))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w(px(0.0))
                        .when(!on, |this| this.opacity(0.6))
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .gap(px(4.0))
                                .text_color(t.ink)
                                .child(
                                    div()
                                        .text_size(px(12.0))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(fg)
                                        .child(render::effect_word(grant.effect)),
                                )
                                .child(text(grant.id.clone())),
                        )
                        .child(mono(grant.permission.clone()).text_color(t.mute).text_size(px(12.0))),
                )
                .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                    this.select(Field::Grants, i);
                    this.on_toggle(&Toggle, window, cx);
                }))
        });
        let added = inspector.added().iter().map(|grant| {
            div()
                .flex()
                .items_center()
                .gap(px(6.0))
                .py(px(5.0))
                .px(px(8.0))
                .child(label(None, "simulado", t.caution()))
                .child(text(grant.id.clone()))
                .child(mono(grant.permission.clone()).text_color(t.mute))
        });
        div()
            .flex()
            .flex_col()
            .child(sidebar_title(t, "Grants", Some("Espaço liga e desliga"), active))
            .children(rows)
            .children(added)
    }

    /// O vazio de uma aba sem cenário: arquivo passado e ilegível aponta a faixa de erro; nenhum arquivo ensina a flag.
    fn no_scenario(&self, purpose: &str) -> String {
        match &self.scenario_path {
            Some(_) => "O cenário não pôde ser lido: veja o erro acima.".to_string(),
            None => format!("Abra um cenário com --scenario para {purpose}."),
        }
    }

    fn evaluate_tab(&self, t: Tokens, cx: &mut Context<Self>) -> Div {
        let (subjects, permissions, resources) = self.names();
        let sidebar = div()
            .flex()
            .flex_col()
            .flex_none()
            .gap(px(6.0))
            .w(px(300.0))
            .h_full()
            .p(px(12.0))
            .bg(t.panel)
            .border_r_1()
            .border_color(t.line)
            .when(self.inspector.is_some(), |sidebar| {
                sidebar
                    .child(self.picker(t, Field::Subject, &subjects, cx))
                    .child(self.picker(t, Field::Permission, &permissions, cx))
                    .child(self.picker(t, Field::Resource, &resources, cx))
                    .child(self.grant_toggles(t, cx))
            })
            .child(shortcuts(t))
            .overflow_y_scrollbar();
        let body = match (self.current(), &self.inspector) {
            (Some((now, baseline)), Some(inspector)) => {
                let sim = self.simulating().then(|| Sim {
                    baseline: &baseline,
                    grants: &inspector.scenario().grants,
                    enabled: inspector
                        .scenario()
                        .grants
                        .iter()
                        .map(|g| inspector.is_enabled(&g.id))
                        .collect(),
                });
                explanation_panel(t, &now, sim)
            }
            _ => empty(t, self.no_scenario("avaliar")),
        };
        div().flex().flex_1().min_h(px(0.0)).child(sidebar).child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .h_full()
                .child(div().w_full().px(px(32.0)).py(px(24.0)).child(body))
                .overflow_y_scrollbar(),
        )
    }

    fn matrix_tab(&self, t: Tokens, cx: &mut Context<Self>) -> Div {
        let (_, _, resources) = self.names();
        let Some(inspector) = &self.inspector else {
            return empty(t, self.no_scenario("ver a matriz"));
        };
        let Some(matrix) = resources.get(self.resource).and_then(|r| inspector.matrix(r).ok()) else {
            return empty(t, "O cenário não declara recursos.");
        };
        let chooser = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(6.0))
            .child(div().text_color(t.mute).mr(px(4.0)).child("Recurso"))
            .children(resources.iter().enumerate().map(|(i, name)| {
                let on = i == self.resource;
                div()
                    .id(("matrix-resource", i))
                    .flex()
                    .items_center()
                    .h(px(28.0))
                    .px(px(12.0))
                    .rounded_full()
                    .border_1()
                    .cursor_pointer()
                    .border_color(if on && self.ring {
                        t.jade
                    } else if on {
                        t.jade_line
                    } else {
                        t.line
                    })
                    .bg(if on { t.jade_soft } else { t.bg })
                    .text_color(if on { t.jade } else { t.ink })
                    .hover(move |s| s.bg(t.sunk))
                    .child(mono(name.clone()))
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        this.resource = i;
                        cx.notify();
                    }))
            }))
            .child(
                div()
                    .ml(px(8.0))
                    .text_size(px(12.0))
                    .text_color(t.mute)
                    .child("setas trocam o recurso"),
            );
        let resource = resources.get(self.resource).cloned().unwrap_or_default();
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h(px(0.0))
            .px(px(32.0))
            .py(px(24.0))
            .gap(px(16.0))
            .child(chooser)
            .child(
                div()
                    .flex_1()
                    .min_h(px(0.0))
                    .child(matrix_table(t, &matrix, &resource, cx))
                    .overflow_scrollbar(),
            )
    }

    fn audit_tab(&self, t: Tokens, cx: &mut Context<Self>) -> Div {
        let Some(trail) = &self.trail else {
            return empty(t, "Abra uma trilha com --audit (JSON Lines gerado por JsonLinesAudit).");
        };
        let chain = trail.chain();
        let (chain_icon, chain_tone) = match chain {
            ChainStatus::Broken(_) => ("x", t.effect(Effect::Deny)),
            ChainStatus::Intact { .. } => ("check", t.effect(Effect::Allow)),
            ChainStatus::Absent => ("info", t.quiet()),
        };
        let list = div()
            .flex()
            .flex_col()
            .flex_none()
            .gap(px(2.0))
            .w(px(420.0))
            .h_full()
            .p(px(12.0))
            .bg(t.panel)
            .border_r_1()
            .border_color(t.line)
            .child(note(t, chain_icon, chain_text(&chain), chain_tone).mb(px(8.0)))
            .child(sidebar_title(t, "Registros", Some("setas navegam"), self.ring))
            .children(trail.records.iter().enumerate().map(|(i, record)| {
                let on = i == self.record;
                div()
                    .id(("record", i))
                    .flex()
                    .flex_col()
                    .gap(px(4.0))
                    .px(px(8.0))
                    .py(px(7.0))
                    .rounded(px(R2))
                    .border_2()
                    .border_color(self.ring(t, on))
                    .cursor_pointer()
                    .hover(move |s| s.bg(t.sunk))
                    .when(on, |this| this.bg(t.jade_bg))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.0))
                            .child(outcome_label(t, &record.outcome))
                            .child(
                                div()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(t.ink)
                                    .child(action_text(&record.action)),
                            )
                            .child(div().flex_1())
                            .child(mono(timestamp(record.at)).text_color(t.mute).text_size(px(11.5))),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(6.0))
                            .min_w(px(0.0))
                            .text_color(t.mute)
                            .text_size(px(13.0))
                            .child(div().flex_none().child(text(record.actor.clone())))
                            .child(icon("arrow-right", 14.0, t.comment))
                            .child(
                                mono(record.object.clone())
                                    .text_color(t.ink)
                                    .min_w(px(0.0))
                                    .overflow_hidden()
                                    .whitespace_nowrap()
                                    .text_ellipsis(),
                            ),
                    )
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        this.record = i;
                        cx.notify();
                    }))
            }))
            .overflow_y_scrollbar();
        let detail = match trail.records.get(self.record) {
            Some(record) => self.record_detail(t, record),
            None => empty(t, "Trilha vazia."),
        };
        div().flex().flex_1().min_h(px(0.0)).child(list).child(
            div()
                .flex_1()
                .min_w(px(0.0))
                .h_full()
                .child(div().w_full().px(px(32.0)).py(px(24.0)).child(detail))
                .overflow_y_scrollbar(),
        )
    }

    fn record_detail(&self, t: Tokens, record: &AuditRecord) -> Div {
        let json = serde_json::to_string_pretty(record).unwrap_or_default();
        let mut out = div().flex().flex_col().gap(px(16.0));
        if let Some(replay) = self.inspector.as_ref().and_then(|i| Trail::replay(record, i)) {
            out = out.child(replay_box(t, &replay));
        }
        if let Some(explanation) = &record.explanation {
            out = out
                .child(section_heading(
                    t,
                    "Rastro gravado na auditoria",
                    Some("como o motor decidiu na época"),
                ))
                .child(explanation_panel(t, explanation, None));
        }
        out.child(boxed(
            t,
            box_title(t, "Registro", Some(&format!("nível {}", record.level))),
            div()
                .p(px(16.0))
                .font_family(MONO)
                .text_size(px(12.0))
                .text_color(t.ink)
                .child(json_text(t, json)),
        ))
    }
}

/// Os atalhos de teclado, no rodapé da barra lateral.
fn shortcuts(t: Tokens) -> Div {
    let row = |keys: Vec<String>, what: &'static str| {
        div()
            .flex()
            .items_center()
            .gap(px(4.0))
            .children(keys.into_iter().map(|k| kbd(t, k)))
            .child(div().ml(px(4.0)).child(what))
    };
    div()
        .flex()
        .flex_col()
        .gap(px(6.0))
        .mt(px(12.0))
        .mx(px(8.0))
        .text_size(px(12.0))
        .text_color(t.mute)
        .child(div().font_weight(FontWeight::SEMIBOLD).child("Teclado"))
        .child(row(vec!["↑".into(), "↓".into()], "escolhe na lista"))
        .child(row(vec!["Tab".into()], "troca de lista"))
        .child(row(vec!["Espaço".into()], "liga ou desliga o grant"))
        .child(row(vec![shortcut("1"), shortcut("2"), shortcut("3")], "abas"))
        .child(row(vec![shortcut("R")], "recarrega"))
        .child(row(vec![shortcut("Z")], "desfaz a simulação"))
}

fn sidebar_title(t: Tokens, title: &str, sub: Option<&str>, active: bool) -> Div {
    div()
        .flex()
        .gap(px(4.0))
        .mt(px(10.0))
        .mb(px(4.0))
        .mx(px(8.0))
        .text_size(px(12.0))
        .text_color(if active { t.jade } else { t.mute })
        .child(div().font_weight(FontWeight::SEMIBOLD).child(text(title.to_string())))
        .when_some(sub, |this, sub| {
            this.child(div().text_color(t.mute).child(text(format!("· {sub}"))))
        })
}

fn checkbox(t: Tokens, on: bool) -> Div {
    div()
        .flex()
        .flex_none()
        .items_center()
        .justify_center()
        .mt(px(2.0))
        .size(px(16.0))
        .rounded(px(R1))
        .border_1()
        .when(on, |this| {
            this.bg(t.jade).border_color(t.jade).child(icon("check", 12.0, t.bg))
        })
        .when(!on, |this| this.bg(t.bg).border_color(t.line))
}

fn section_heading(t: Tokens, title: &str, sub: Option<&str>) -> Div {
    div()
        .flex()
        .items_baseline()
        .gap(px(8.0))
        .mt(px(4.0))
        .child(
            div()
                .text_size(px(11.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(t.jade)
                .child(caps(title)),
        )
        .when_some(sub, |this, sub| {
            this.child(div().text_color(t.mute).child(text(sub.to_string())))
        })
}

/// Aviso em faixa: ícone + texto, no tom do estado.
fn note(t: Tokens, icon_name: &str, body: impl IntoElement, tone: Tone) -> Div {
    let (fg, bg, line) = tone;
    div()
        .flex()
        .items_start()
        .gap(px(8.0))
        .px(px(14.0))
        .py(px(10.0))
        .rounded(px(R2))
        .border_1()
        .border_color(line)
        .bg(bg)
        .text_color(t.ink)
        .child(div().mt(px(2.0)).child(icon(icon_name, 16.0, fg)))
        .child(div().flex_1().min_w(px(0.0)).child(body))
}

fn empty(t: Tokens, message: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_1()
        .items_center()
        .justify_center()
        .p(px(24.0))
        .text_color(t.mute)
        .child(message.into())
}

fn fact(t: Tokens, name: impl Into<SharedString>, value: impl IntoElement) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(px(2.0))
        .child(div().text_size(px(12.0)).text_color(t.mute).child(name.into()))
        .child(div().font_weight(FontWeight::MEDIUM).text_color(t.ink).child(value))
}

/// O rastro de uma decisão: veredito, caminho do recurso e a linha do tempo dos grants.
fn explanation_panel(t: Tokens, e: &Explanation, sim: Option<Sim>) -> Div {
    let effect = e.decision.effect;
    let decisive = e.decisive();
    let why = insight(e);
    let focus_rank = decisive.and_then(|g| g.rank).or(why.as_ref().and_then(|w| w.rank));
    let subject = e.subject.id.clone().unwrap_or_else(|| e.subject.kind.clone());
    let state_caption = match effect {
        Effect::Allow => "Permitido",
        Effect::Deny => "Negado",
    };
    let (state_fg, _, _) = t.effect(effect);
    let state = div()
        .flex()
        .flex_none()
        .items_center()
        .gap(px(12.0))
        .child(seal(t, effect, 48.0))
        .child(
            div()
                .text_size(px(20.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(state_fg)
                .child(caps(state_caption)),
        );
    let ask = div()
        .flex()
        .flex_wrap()
        .items_baseline()
        .gap(px(6.0))
        .text_size(px(20.0))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(t.ink)
        .child(text(format!("{subject} pede")))
        .child(
            div()
                .font_family(MONO)
                .text_size(px(17.0))
                .child(text(e.permission.clone())),
        );
    let compare = sim
        .as_ref()
        .map(|s| s.baseline)
        .filter(|b| b.decision.effect != effect)
        .map(|b| {
            note(
                t,
                "alert",
                text(format!(
                    "Com os grants originais, o pedido seria {}: {}.",
                    effect_text(b.decision.effect),
                    render::reason(&b.decision.reason)
                )),
                t.caution(),
            )
        });
    let reason_row = div()
        .flex()
        .flex_wrap()
        .items_center()
        .gap(px(24.0))
        .px(px(16.0))
        .py(px(14.0))
        .border_b_1()
        .border_color(t.line)
        .child(
            div()
                .flex()
                .flex_1()
                .min_w(px(260.0))
                .gap(px(8.0))
                .child(div().flex_none().text_color(t.mute).child("Motivo"))
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .text_color(t.ink)
                        .child(text(render::reason(&e.decision.reason))),
                ),
        )
        .when_some(why.as_ref(), |this, why| {
            let body = div()
                .flex()
                .flex_col()
                .gap(px(2.0))
                .child(text(why.lead.clone()))
                .when_some(why.expression.clone(), |this, expr| this.child(mono(expr)));
            this.child(
                note(t, "info", body, t.info())
                    .flex_1()
                    .min_w(px(260.0))
                    .max_w(px(520.0)),
            )
        });
    let facts = div()
        .flex()
        .flex_wrap()
        .gap_x(px(32.0))
        .gap_y(px(10.0))
        .px(px(16.0))
        .py(px(12.0))
        .child(fact(
            t,
            "Papéis efetivos",
            text(if e.roles.is_empty() {
                "nenhum".to_string()
            } else {
                e.roles.join(", ")
            }),
        ))
        .child(fact(t, "Permissões que concedem", mono(e.effective.join(", "))))
        .child(fact(t, "Estratégia", mono(e.strategy.clone())))
        .children(e.overrides.iter().map(|step| {
            fact(
                t,
                format!("Override {}", step.name),
                text(render::override_outcome(step.outcome)),
            )
        }));
    let warnings = e
        .decision
        .warnings
        .iter()
        .map(|w| note(t, "alert", text(w.clone()), t.caution()));
    let verdict = div()
        .flex()
        .flex_col()
        .border_1()
        .border_color(t.line)
        .rounded(px(R2))
        .overflow_hidden()
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(12.0))
                .min_h(px(60.0))
                .py(px(10.0))
                .px(px(16.0))
                .bg(t.effect(effect).1)
                .border_b_1()
                .border_color(t.line)
                .child(state)
                .child(ask),
        )
        .child(reason_row)
        .child(facts);
    let path = boxed(
        t,
        box_title(t, "Caminho do recurso", Some("degrau · âncora")),
        div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(6.0))
            .px(px(16.0))
            .py(px(14.0))
            .children(e.path.iter().enumerate().map(|(rank, anchor)| {
                let hit = Some(rank) == focus_rank;
                let crumb = div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .h(px(28.0))
                    .pl(px(4.0))
                    .pr(px(10.0))
                    .rounded_full()
                    .border_1()
                    .border_color(if hit { t.jade } else { t.line })
                    .bg(if hit { t.jade_soft } else { t.bg })
                    .text_color(if hit { t.jade } else { t.ink })
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_center()
                            .min_w(px(20.0))
                            .h(px(20.0))
                            .px(px(6.0))
                            .rounded_full()
                            .bg(if hit { t.jade } else { t.sunk })
                            .text_color(if hit { t.bg } else { t.ink })
                            .text_size(px(12.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(text(rank.to_string())),
                    )
                    .child(mono(anchor.to_string()));
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .gap(px(6.0))
                    .when(rank > 0, |this| this.child(icon("arrow-right", 14.0, t.comment)))
                    .child(crumb)
            })),
    );
    let rows: Vec<AnyElement> = match &sim {
        Some(sim) => {
            let mut rows = Vec::new();
            for (i, grant) in sim.grants.iter().enumerate() {
                let n = (i + 1).to_string();
                if sim.enabled.get(i).copied().unwrap_or(true) {
                    if let Some(trace) = e.grants.iter().find(|t| t.grant.id == grant.id) {
                        rows.push(timeline_item(t, n, trace, effect, decisive).into_any_element());
                    }
                } else {
                    rows.push(disabled_item(t, n, grant).into_any_element());
                }
            }
            for trace in e
                .grants
                .iter()
                .filter(|tr| !sim.grants.iter().any(|g| g.id == tr.grant.id))
            {
                rows.push(timeline_item(t, "+".into(), trace, effect, decisive).into_any_element());
            }
            rows
        }
        None => e
            .grants
            .iter()
            .enumerate()
            .map(|(i, trace)| timeline_item(t, (i + 1).to_string(), trace, effect, decisive).into_any_element())
            .collect(),
    };
    let timeline = div()
        .relative()
        .flex()
        .flex_col()
        .pl(px(4.0))
        .child(
            div()
                .absolute()
                .left(px(19.0))
                .top(px(4.0))
                .bottom(px(4.0))
                .w(px(2.0))
                .bg(t.line),
        )
        .children(rows);
    div()
        .flex()
        .flex_col()
        .gap(px(16.0))
        .child(verdict)
        .when_some(compare, |this, c| this.child(c))
        .children(warnings)
        .child(path)
        .child(section_heading(
            t,
            "Grants entregues pela fonte",
            Some("destino de cada um"),
        ))
        .child(if e.grants.is_empty() && sim.is_none() {
            empty(t, "A fonte não entregou nenhum grant para este pedido.")
        } else {
            timeline
        })
}

/// Identidade e alvo de um grant numa linha que quebra recuada sob o nome.
fn grant_identity(t: Tokens, grant: &Grant, rank: Option<usize>, hot: bool) -> Div {
    div()
        .flex()
        .flex_1()
        .flex_wrap()
        .items_center()
        .gap(px(8.0))
        .min_w(px(0.0))
        .min_h(px(32.0))
        .text_color(if hot { t.ink } else { t.mute })
        .child(
            div()
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(t.ink)
                .child(text(grant.id.clone())),
        )
        .child(effect_label(t, grant.effect))
        .child(mono(grant.permission.clone()))
        .child(icon("arrow-right", 14.0, t.comment))
        .child(text(format!("{} em", render::matcher(&grant.subject))))
        .child(mono(target_text(grant)))
        .when_some(rank, |this, rank| {
            this.child(label(None, format!("degrau {rank}"), (t.jade, t.jade_bg, t.jade_line)))
        })
}

fn timeline_row(t: Tokens, badge: Div, n: String, identity: Div, destination: Div) -> Div {
    div()
        .flex()
        .items_start()
        .gap(px(12.0))
        .child(badge)
        .child(
            div()
                .flex()
                .flex_none()
                .items_center()
                .w(px(16.0))
                .min_h(px(32.0))
                .text_color(t.mute)
                .child(text(n)),
        )
        .child(identity)
        .child(
            div()
                .flex()
                .flex_none()
                .items_center()
                .min_h(px(32.0))
                .child(destination),
        )
}

fn badge(t: Tokens, glyph: &str, fg: Hsla, bg: Hsla) -> Div {
    div()
        .flex()
        .flex_none()
        .items_center()
        .justify_center()
        .size(px(32.0))
        .rounded_full()
        .border_2()
        .border_color(t.bg)
        .bg(bg)
        .child(icon(glyph, 16.0, fg))
}

/// Um grant na linha do tempo: ícone do destino, identidade, alvo e, quando há, a árvore da condição.
fn timeline_item(t: Tokens, n: String, trace: &GrantTrace, outcome: Effect, decisive: Option<&GrantTrace>) -> Div {
    let is_decisive = decisive.is_some_and(|d| std::ptr::eq(d, trace));
    let explains = matches!(
        trace.verdict,
        Verdict::ConditionFalse | Verdict::ConditionUnresolved { .. } | Verdict::SubjectUnresolved { .. }
    ) && trace.grant.effect == Effect::Allow
        && outcome == Effect::Deny;
    let (glyph, fg, bg) = if is_decisive {
        let (fg, _, _) = t.effect(trace.grant.effect);
        (
            if trace.grant.effect == Effect::Allow {
                "check"
            } else {
                "x"
            },
            t.bg,
            fg,
        )
    } else {
        match &trace.verdict {
            Verdict::Candidate | Verdict::CandidateFailSafe { .. } => ("dot", t.jade, t.jade_bg),
            Verdict::ConditionFalse if explains => ("x", t.bg, t.deny),
            Verdict::ConditionFalse => ("x", t.mute, t.sunk),
            Verdict::ConditionUnresolved { .. } | Verdict::SubjectUnresolved { .. } | Verdict::OverrideOnly => {
                ("alert", t.bg, t.gold_ink)
            }
            Verdict::NotReached => ("dot", t.comment, t.sunk),
            _ => ("slash", t.mute, t.sunk),
        }
    };
    let hot = is_decisive || explains || trace.verdict.is_candidate();
    let destination = if is_decisive {
        label(Some("check"), "decisivo", t.effect(trace.grant.effect))
    } else {
        match &trace.verdict {
            Verdict::Candidate | Verdict::CandidateFailSafe { .. } => {
                label(None, render::verdict(&trace.verdict), (t.jade, t.jade_bg, t.jade_line))
            }
            Verdict::ConditionFalse => label(Some("x"), "condição falsa", (t.deny, t.bg, t.deny)),
            Verdict::ConditionUnresolved { .. } | Verdict::SubjectUnresolved { .. } | Verdict::OverrideOnly => {
                label(Some("alert"), render::verdict(&trace.verdict), t.caution())
            }
            _ => div()
                .text_size(px(13.0))
                .text_color(t.mute)
                .child(text(render::verdict(&trace.verdict))),
        }
    };
    div()
        .flex()
        .flex_col()
        .py(px(6.0))
        .child(timeline_row(
            t,
            badge(t, glyph, fg, bg),
            n,
            grant_identity(t, &trace.grant, trace.rank, hot),
            destination,
        ))
        .when_some(trace.condition.as_ref(), |this, condition| {
            this.child(condition_box(t, condition))
        })
}

/// Um grant desligado na simulação, no lugar e com o número originais.
fn disabled_item(t: Tokens, n: String, grant: &Grant) -> Div {
    div().py(px(6.0)).opacity(0.6).child(timeline_row(
        t,
        badge(t, "slash", t.mute, t.sunk),
        n,
        grant_identity(t, grant, None, false),
        label(None, "desligado na simulação", t.caution()),
    ))
}

fn condition_box(t: Tokens, root: &ConditionTrace) -> Div {
    let mut rows = Vec::new();
    condition_rows(t, root, 0, &mut rows);
    div()
        .ml(px(84.0))
        .mt(px(6.0))
        .mb(px(4.0))
        .flex()
        .flex_col()
        .border_1()
        .border_color(t.line)
        .rounded(px(R2))
        .overflow_hidden()
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(8.0))
                .h(px(38.0))
                .px(px(16.0))
                .bg(t.panel)
                .border_b_1()
                .border_color(t.line)
                .text_size(px(13.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(t.ink)
                .child(icon("chevron-down", 14.0, t.mute))
                .child("Árvore da condição"),
        )
        .children(rows)
}

fn condition_rows(t: Tokens, node: &ConditionTrace, depth: usize, out: &mut Vec<Div>) {
    let (glyph, color) = match node.result {
        TraceResult::True => ("check", t.jade),
        TraceResult::False => ("x", t.deny),
        TraceResult::Error(_) => ("alert", t.gold_ink),
        TraceResult::Skipped => ("dot", t.comment),
    };
    let skipped = matches!(node.result, TraceResult::Skipped);
    let detail = match &node.result {
        TraceResult::Error(problem) => Some(format!("erro: {problem}")),
        TraceResult::Skipped => Some("não avaliado: curto-circuito".to_string()),
        _ => None,
    };
    let first = out.is_empty();
    out.push(
        div()
            .flex()
            .items_center()
            .gap(px(8.0))
            .min_h(px(34.0))
            .pl(px(16.0))
            .pr(px(16.0))
            .when(!first, |this| this.border_t_1().border_color(t.line))
            .children((0..depth).map(|_| div().w(px(1.0)).h(px(34.0)).mr(px(11.0)).bg(t.line)))
            .child(icon(glyph, 14.0, color))
            .child(mono(node.label.clone()).text_color(if skipped { t.mute } else { t.ink }))
            .when_some(detail, |this, detail| {
                this.child(
                    div()
                        .ml(px(8.0))
                        .italic()
                        .text_size(px(13.0))
                        .text_color(t.mute)
                        .child(detail),
                )
            }),
    );
    for child in &node.children {
        condition_rows(t, child, depth + 1, out);
    }
}

fn matrix_table(t: Tokens, matrix: &Matrix, resource: &str, cx: &mut Context<InspectView>) -> Div {
    let first_w = px(300.0);
    let cell_w = px(150.0);
    let header = div()
        .flex()
        .items_center()
        .h(px(40.0))
        .px(px(16.0))
        .bg(t.panel)
        .border_b_1()
        .border_color(t.line)
        .text_size(px(12.0))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(t.mute)
        .child(div().w(first_w).child("Permissão"))
        .children(matrix.subjects.iter().map(|s| div().w(cell_w).child(text(s.clone()))));
    let rows = matrix.permissions.iter().enumerate().map(|(pi, permission)| {
        div()
            .flex()
            .items_center()
            .min_h(px(44.0))
            .px(px(16.0))
            .when(pi > 0, |this| this.border_t_1().border_color(t.line))
            .child(div().w(first_w).child(mono(permission.clone()).text_color(t.ink)))
            .children((0..matrix.subjects.len()).map(|si| {
                let effect = matrix.cells[pi][si];
                let before = matrix.baseline[pi][si];
                let changed = matrix.changed(pi, si);
                let (fg, bg, line) = t.effect(effect);
                let caption = match effect {
                    Effect::Allow => "sim",
                    Effect::Deny => "não",
                };
                let glyph = if effect == Effect::Allow { "check" } else { "x" };
                div().w(cell_w).child(
                    div()
                        .id(("cell", pi * 10_000 + si))
                        .flex()
                        .items_center()
                        .gap(px(6.0))
                        .cursor_pointer()
                        .child(
                            label(
                                Some(glyph),
                                caption,
                                if changed { (fg, bg, t.gold_line) } else { (fg, bg, line) },
                            )
                            .hover(move |s| s.border_color(t.jade)),
                        )
                        .when(changed, |this| {
                            let was = if before == Effect::Allow { "sim" } else { "não" };
                            this.child(
                                div()
                                    .text_size(px(12.0))
                                    .text_color(t.gold_ink)
                                    .child(text(format!("antes: {was}"))),
                            )
                        })
                        .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                            this.subject = si;
                            this.permission = pi;
                            this.tab = Tab::Evaluate;
                            cx.notify();
                        })),
                )
            }))
    });
    let footer = match matrix.changes().len() {
        0 => "Clique numa célula para ver o rastro.".to_string(),
        1 => "1 célula mudou em relação aos grants originais. Clique numa célula para ver o rastro.".to_string(),
        n => format!("{n} células mudaram em relação aos grants originais. Clique numa célula para ver o rastro."),
    };
    div()
        .flex()
        .flex_col()
        .gap(px(12.0))
        .child(boxed(
            t,
            box_title(
                t,
                "Quem pode o quê",
                Some(&format!("permissões × sujeitos em {resource}")),
            ),
            div().flex().flex_col().child(header).children(rows),
        ))
        .child(div().text_color(t.mute).child(text(footer)))
}

fn replay_box(t: Tokens, replay: &Replay) -> Div {
    let changed = replay.changed();
    let message = if changed {
        "A decisão mudou: a política ou os grants de hoje decidem diferente do que foi gravado."
    } else {
        "A política e os grants de hoje decidem igual ao que foi gravado."
    };
    let (fg, bg, _) = if changed { t.caution() } else { t.effect(Effect::Allow) };
    div()
        .flex()
        .flex_col()
        .gap(px(16.0))
        .child(boxed(
            t,
            div()
                .flex()
                .flex_1()
                .flex_wrap()
                .items_center()
                .gap(px(10.0))
                .child(box_title(t, "Reavaliação", Some("com a política e os grants atuais")))
                .child(div().flex_1())
                .child(div().text_color(t.mute).text_size(px(13.0)).child("gravado"))
                .child(outcome_label(t, &replay.recorded))
                .child(div().text_color(t.mute).text_size(px(13.0)).child("hoje"))
                .child(effect_now(t, replay.now.decision.effect)),
            div()
                .flex()
                .items_start()
                .gap(px(8.0))
                .px(px(16.0))
                .py(px(12.0))
                .bg(bg)
                .child(
                    div()
                        .mt(px(2.0))
                        .child(icon(if changed { "alert" } else { "check" }, 16.0, fg)),
                )
                .child(message),
        ))
        .child(explanation_panel(t, &replay.now, None))
}

fn effect_now(t: Tokens, effect: Effect) -> Div {
    match effect {
        Effect::Allow => label(Some("check"), "permitido", t.effect(effect)),
        Effect::Deny => label(Some("x"), "negado", t.effect(effect)),
    }
}

impl Render for InspectView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens(is_dark(window));
        self.ring = self.keyboard && self.focus.is_focused(window);
        let body = match self.tab {
            Tab::Evaluate => self.evaluate_tab(t, cx),
            Tab::Matrix => self.matrix_tab(t, cx),
            Tab::Audit => self.audit_tab(t, cx),
        };
        let errors = self
            .errors
            .iter()
            .map(|e| note(t, "alert", text(e.clone()), t.error()).mx(px(24.0)).mt(px(12.0)));
        div()
            .key_context(KEY_CONTEXT)
            .track_focus(&self.focus)
            .on_mouse_down(
                gpui::MouseButton::Left,
                cx.listener(|this, _: &gpui::MouseDownEvent, _, cx| {
                    if this.keyboard {
                        this.keyboard = false;
                        cx.notify();
                    }
                }),
            )
            .on_action(cx.listener(Self::on_up))
            .on_action(cx.listener(Self::on_down))
            .on_action(cx.listener(Self::on_next_list))
            .on_action(cx.listener(Self::on_prev_list))
            .on_action(cx.listener(Self::on_toggle))
            .on_action(cx.listener(|this, _: &ShowEvaluate, _, cx| this.show(Tab::Evaluate, cx)))
            .on_action(cx.listener(|this, _: &ShowMatrix, _, cx| this.show(Tab::Matrix, cx)))
            .on_action(cx.listener(|this, _: &ShowAudit, _, cx| this.show(Tab::Audit, cx)))
            .on_action(cx.listener(Self::on_reload))
            .on_action(cx.listener(Self::on_undo))
            .size_full()
            .flex()
            .flex_col()
            .bg(t.bg)
            .font_family(SANS)
            .text_color(t.ink)
            .text_size(px(14.0))
            .child(self.header(t, cx))
            .children(errors)
            .child(body)
    }
}
