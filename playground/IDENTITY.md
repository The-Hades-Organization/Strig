# Visual identity of the playground

## Concept

Strig's mark is a full moon with a bite taken out of it; the fangs are the shape of the missing piece.
The playground applies that to what it shows. The **seal** of the ruling is the mark itself: on *allow*
the moon is whole, on *deny* the fangs bite in from the top, and while a ruling is on hold the bite is
half way. The reader sees the word, then the shape, and only then the colour, so allow and deny never
depend on colour alone.

The use is operating a tool (edit, read the error, ask "why"), so the interface is sober: fixed
columns, native controls, no decoration that gets in the way of reading code. The personality lives
in the details: the seal, the bite animation, the ruby mark next to the wordmark.

The palette, the wordmark and the rules come from the brand sheet (`brand/` in the docs site repository).

## Where each choice comes from

| Choice | Origin in the brand |
|---|---|
| White page, warm-grey cards, near-black dark theme | `#FFFFFF` and `#0A0A0A` backgrounds, tinted toward the support colour |
| Ruby for the mark and for *deny* | primary `#B01030` on light, `#FF5E70` on dark |
| Rose-grey for structure, selection and focus ornament | support colour `#996C6C`, darkened where it is text |
| Green for *allow* | a functional colour the brand does not define; it never shares a hue with the others |
| Amber only for caution: who, where, numbers, a ruling on hold | functional, kept away from the brand reds |
| Violet only for errors in the text | the one hue no ruling uses |
| Wordmark in the header | the Cinzel Medium lettering of the brand, outlined |
| Seal: whole moon (allow), bitten moon (deny) | the mark and its fangs |

Cinzel is used only for the wordmark, and as outlines, so the page embeds no font. Labels, tabs and
the ruling word are the UI sans in capitals with spacing.

## Tokens

### Colour (contrast checked, WCAG 2.x)

Body text needs 4.5:1 and interface elements 3:1. The ratios were measured with the relative
luminance formula; the lowest of each role are below.

| Role | Light | Dark | Lowest contrast |
|---|---|---|---|
| `bg` page | `#FFFFFF` | `#0A0A0A` | |
| `panel` cards | `#F8F6F6` | `#141212` | |
| `sunk` editor well | `#F1EEEE` | `#070707` | |
| `line` / `line-strong` | `#E4DEDE` / `#CFC5C5` | `#2A2424` / `#3F3535` | decorative |
| `ink` text | `#111111` | `#F2F2F2` | 16.4 light (on the well) · 17.7 dark |
| `mute` secondary text | `#5C4A4A` | `#BFAAAA` | 7.2 light (on the well) · 8.5 dark |
| `jade` structure and selection | `#7D4A4A` | `#E0A8A8` | 5.9 on `jade-bg` · 8.0 dark |
| `allow` | `#1B6B3A` | `#5FD08A` | 5.5 on `allow-bg` · 7.4 dark |
| `gold-ink` who, where, numbers | `#6F5200` | `#E3B04B` | 6.1 on `gold-bg` · 7.7 dark |
| `deny` | `#B01030` | `#FF5E70` | 5.9 on `deny-bg` · 5.5 dark |
| `err` | `#7A35B5` | `#C9A0F0` | 6.5 light (on the card) · 8.7 dark |
| `comment` | `#665252` | `#B09A9A` | 6.1 on `gold-bg` · 5.8 dark |
| `gold` (ornament and focus only) | `#996C6C` | `#B88282` | 4.1 on the card · 5.8 dark (3:1 needed) |
| tinted backgrounds | `jade-bg #F3E6E6`, `allow-bg #DDF1E4`, `gold-bg #F5EBCB`, `deny-bg #FBE4E8` | `#2E1C1C`, `#12301E`, `#2E2410`, `#3A141A` | |

Two reds exist on purpose: the ruby is the brand and the *deny* ruling, and the brand sheet asks for it
to stay out of body text. Here it is text only as the ruling word and the *deny* tokens in the code,
always next to an icon or the word.

### Typography

The page embeds no font; every stack ends in what the system has.

- **Interface:** the system sans-serif stack. 14/20; 12.5 for support text; 600 for item titles.
- **Code and data:** the system monospace stack. 13.5/22, ligatures off, tabular figures in the gutter.
- **Labels (tabs, "Cases", the ruling word):** the interface sans in capitals, 11 px with 0.16 em of
  spacing (ruling: 26 px, 0.14 em).
- **Mark:** the Cinzel Medium wordmark of the brand as vector outlines, not a font.

### Spacing, radii, motion

- Space: 4, 8, 12, 16, 24, 32, 48.
- Radii: 4 (inline code), 8 (controls), 14 (cards), pill (status, line shortcut).
- Shadow: a soft vertical offset, never a ring with no offset.
- Motion: curve `cubic-bezier(.16, 1, .3, 1)`; 120 ms (hover), 220 ms (tab, switch), 720 ms (seal).
  **One authored moment:** when the ruling appears, the fangs of the seal bite in (deny) or retract
  (allow). With `prefers-reduced-motion` everything drops to 1 ms.
