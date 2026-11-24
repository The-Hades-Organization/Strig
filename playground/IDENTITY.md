# Visual identity of the playground

## Concept

Themis decides without looking at who is asking: the blindfold, the scales, the gilt knot. The
playground applies that to what it shows. The **band tilted by 9°** in the icon is the motif of the
page, and the **seal** of the ruling is the icon itself: on *allow* the band opens, on *deny* it
closes, and the gilt knot ties the decision. The reader sees the word, then the shape, and only then
the colour, so allow and deny never depend on colour alone.

The use is operating a tool (edit, read the error, ask "why"), so the interface is sober: fixed
columns, native controls, no decoration that gets in the way of reading code. The personality lives
in the details: the seal, the band behind the ruling, the gilt knot that follows the chosen syntax,
the spaced Roman capitals of the labels.

## Where each choice comes from

| Choice | Origin in the banner |
|---|---|
| Ivory page, lighter ivory cards, darker ivory editor well | `#F1F0EB`, `#DAD6CA` (border) |
| Dark theme in near-black green | `#16201D`, `#26352F` |
| Green as the colour of structure and of *allow* | `#1F5C51` (light), `#9FC0B2` and derivatives (dark) |
| Gold only as ornament, focus, and "who/where" | `#B07D1E`, `#E3B04B` |
| Band at −9° behind the ruling and in the seal | the band of the icon (`rotate(-9)`) |
| Allow seal (open band) and deny seal (closed band) | the split disc of the icon |
| Gilt knot in the syntax switch | the knot of the icon |
| "THEMIS" mark at the top | the lettering of the banner itself (not a font) |
| Spaced Roman capitals for labels | the capitals of the banner |
| Large radii on cards, a circle for the seal | the `rx` of the banner and the disc |

Deny and error do not exist in the banner. A **clay** (`#8E3226` / `#F0A08D`) is derived from the same
warmth as the gold, so no red is imported from another system. Deny is a decision (closed seal, the
word, a cross icon); error is a defect in the text (a wavy underline under the span, an exclamation
icon). The two never share a shape.

## Tokens

### Colour (contrast checked, WCAG 2.x)

Body text needs 4.5:1 and interface elements 3:1. The ratios were measured with the relative
luminance formula; the lowest of each role are below.

| Role | Light | Dark | Lowest contrast |
|---|---|---|---|
| `bg` page | `#F1F0EB` | `#16201D` | |
| `panel` cards | `#F8F7F3` | `#1B2824` | |
| `sunk` editor well | `#ECEAE2` | `#131B19` | |
| `line` / `line-strong` | `#DAD6CA` / `#BDB8A8` | `#26352F` / `#3A5047` | decorative |
| `ink` text | `#16201D` | `#E9E2D0` | 13.9 light · 11.8 dark |
| `mute` secondary text | `#4E6B63` | `#9FC0B2` | 4.8 light (on the well) · 7.8 dark |
| `jade` structure and allow | `#1F5C51` | `#7CC3AE` | 6.1 on `jade-bg` · 6.0 dark |
| `gold-ink` who, where, numbers | `#7A5410` | `#E3B04B` | 5.3 on `gold-bg` · 6.5 dark |
| `deny` | `#8E3226` | `#F0A08D` | 6.2 on `deny-bg` · 6.9 dark |
| `err` | `#B0301F` | `#F4906F` | 5.3 light · 6.6 dark |
| `comment` | `#496359` | `#8DAA9F` | 5.1 on `gold-bg` · 5.1 dark |
| `gold` (ornament and focus only) | `#B07D1E` | `#E3B04B` | 3.2 light (focus ring, not text) · 7.7 dark |
| tinted backgrounds | `jade-bg #DAE8E1`, `gold-bg #F0E3C2`, `deny-bg #F3DED6` | `#1F3A33`, `#3A3118`, `#3C2420` | |

The banner gold (`#B07D1E`) fails as text on light (3.2:1). So there are two: `gold` for ornament and
focus, and the darker `gold-ink` for text.

### Typography

The page embeds no font; every stack ends in what the system has.

- **Interface:** the system sans-serif stack. 14/20; 12.5 for support text; 600 for item titles.
- **Code and data:** the system monospace stack. 13.5/22, ligatures off, tabular figures in the gutter.
- **Labels (tabs, "Cases", the ruling word):** a Roman serif in capitals, 11 px with 0.16 em of
  spacing (ruling: 26 px, 0.14 em). The stack prefers classical Roman faces and falls back to a
  generic serif.
- **Mark:** the vector lettering of the banner, not a font.

### Spacing, radii, motion

- Space: 4, 8, 12, 16, 24, 32, 48.
- Radii: 4 (inline code), 8 (controls), 14 (cards), pill (status, line shortcut).
- Shadow: a soft vertical offset, never a ring with no offset.
- Motion: curve `cubic-bezier(.16, 1, .3, 1)`; 120 ms (hover), 220 ms (tab, switch), 720 ms (seal).
  **One authored moment:** when the ruling appears, the band of the seal opens (allow) or closes
  (deny) and the knot ties. With `prefers-reduced-motion` everything drops to 1 ms.
- Angle: −9°, the one of the band. It appears in the seal and in the band behind the ruling, and
  nowhere else.

### Browser surfaces

Green text selection, gold caret, thin scrollbars in the border colour, a 2 px gold focus ring with an
offset, tabular figures in the gutter. Nothing is left at the browser default.

## Syntax highlighting

Colour follows the **role of the word in the decision**, not the token class.

| Role | Example | Colour |
|---|---|---|
| Declares something | `permission`, `role`, `kinds`, `grant` | `jade`, 600 |
| Relates things | `depends_on`, `inherits`, `when`, `on`, `in` | `mute` |
| Who and where | `user:ana`, `org:acme` | `gold-ink` |
| What is asked | `document.edit` | `ink` |
| Grant id | `g-edit` | `ink`, 700 |
| Effect | `allow` / `deny` | `jade` / clay label, 700 |
| Number, boolean | `3`, `true` | `gold-ink` |
| Quoted text | `"legal"` | `mute`, italic |
| Comment | `// never alone` | `comment`, italic |
| Problem | `doc.write` | `err` wavy underline, 1.5 px |

That is why `allow` and `deny` read at a glance in the middle of code, and why the grant cited by a
ruling gets a gold band on its line (with the line number in gold).

## What the page does

- Four cases in the three syntaxes. The source is editable.
- The source is compiled by the engine on every edit. The count ("Compiles: 3 permissions, 2 grants")
  and the problems come from its diagnostics. Clicking a problem puts the caret on the span; the line
  gets the wavy underline and its number turns red.
- The problems panel shows `file:line:column`, the message and the hint.
- Each case asks questions; the ruling and its trace come from the engine's explanation. "Show g-…"
  jumps to the grant in the source.
- Switching syntax converts the text the reader has on screen to the other syntax.
- Tabs Evaluate, JSON and About. The JSON is the canonical document the compiler produced.
- Light and dark themes (follows the system; the button flips it).
- 1280 px in three columns; 390 px in one column, with no horizontal page scroll.

## Left for later

1. **An embedded label font.** The Roman serif uses the system stack; without a classical Roman face it
   falls back to a generic serif. Embedding an uppercase Roman face with a free licence would close it.
2. **Real editing.** Undo through the browser stack works; auto-indent, line comment toggle and search
   are missing.
3. **Several files** (`Project`): file tabs, each with its own `language`.
4. **The newest conditions** in the highlighting and the examples, once they are released.
5. **A formatter** as a button, once the binding has one.
