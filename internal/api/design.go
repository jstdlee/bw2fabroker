package api

// designCSS is the shared look for the admin panel and the guides: a soft grey page,
// white cards, one accent, small type, and a status lamp that always has a word next to it.
const designCSS = `
:root {
  color-scheme: light dark;
  --bg: #f4f4f6;
  --card: #ffffff;
  --line: #e3e3e8;
  --divider: #ececf0;
  --fg: #212126;
  --dim: #737379;
  --track: #f1f1f4;
  --accent: #007aff;
  --ok: #1d7a3a;
  --warn: #a05a00;
  --bad: #d70015;
  --shadow: 0 1px 2px rgba(0,0,0,.04);
  font: 13px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  -webkit-text-size-adjust: 100%;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1c1c1f;
    --card: #252528;
    --line: #303034;
    --divider: #2c2c30;
    --fg: #e8e8ec;
    --dim: #8e8e96;
    --track: #2e2e33;
    --accent: #0a84ff;
    --ok: #4fd07a;
    --warn: #ffb340;
    --bad: #ff453a;
    --shadow: none;
  }
}
@media (prefers-contrast: more) {
  :root { --dim: #5c5c63; --line: #b9b9c0; --divider: #c9c9d0; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); }
main { max-width: 46rem; margin: 0 auto; padding: 22px 16px 72px; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
h1 { font-size: 19px; font-weight: 600; letter-spacing: -.01em; margin: 0; }
h2 { font-size: 11px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; color: var(--dim); margin: 22px 0 7px; }
p { margin: 6px 0; }
.lead { color: var(--dim); margin: 3px 0 0; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; box-shadow: var(--shadow); margin: 0 0 12px; overflow: hidden; }
.row { display: flex; align-items: center; gap: 12px; padding: 10px 14px; border-top: 1px solid var(--divider); flex-wrap: wrap; }
.row:first-child { border-top: 0; }
.row.wrap { flex-wrap: wrap; }
.row .t { font-size: 13px; }
.row .d { font-size: 11.5px; color: var(--dim); margin-top: 1px; }
.row .grow { flex: 1 1 14rem; min-width: 9rem; }
.row .c { margin-left: auto; display: flex; align-items: center; gap: 8px; flex: 0 0 auto; }
.row.stack { display: block; }
.stack .t { margin-bottom: 2px; }
.stack .c { margin: 8px 0 0; justify-content: flex-start; }
ul.list { list-style: none; margin: 0; padding: 0; }
ul.list > li { display: flex; align-items: center; gap: 10px; padding: 9px 14px; border-top: 1px solid var(--divider); }
ul.list > li:first-child { border-top: 0; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; }
code { background: var(--track); border-radius: 4px; padding: 1px 5px; overflow-wrap: anywhere; }
pre { background: var(--track); border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; overflow-x: auto; margin: 8px 0 0; line-height: 1.5; }
pre code { background: none; padding: 0; }
input, select, textarea { font: inherit; color: var(--fg); background: var(--track); border: 1px solid transparent; border-radius: 6px; padding: 5px 8px; min-height: 27px; width: 100%; }
input:focus, select:focus, textarea:focus { outline: 3px solid color-mix(in srgb, var(--accent) 45%, transparent); outline-offset: 1px; border-color: var(--accent); }
input.wide { width: 22rem; max-width: 100%; }
button, .btn { font: inherit; color: var(--fg); background: var(--track); border: 1px solid var(--line); border-radius: 6px; padding: 4px 10px; min-height: 27px; cursor: default; user-select: none; }
button:hover, .btn:hover { background: color-mix(in srgb, var(--track) 80%, var(--fg)); }
button:active, .btn:active { transform: scale(.98); }
button.primary { background: var(--accent); border-color: transparent; color: #fff; }
button.primary:hover { background: color-mix(in srgb, var(--accent) 88%, #000); }
button.danger { background: transparent; border-color: transparent; color: var(--bad); }
button.danger:hover { background: color-mix(in srgb, var(--bad) 10%, transparent); }
button.quiet { background: transparent; border-color: var(--line); }
button:focus-visible, .btn:focus-visible { outline: 3px solid color-mix(in srgb, var(--accent) 45%, transparent); outline-offset: 1px; }
button[disabled] { opacity: .45; }
form.inline { display: inline; }
.f { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.f input { width: 15rem; max-width: 100%; }
.f.tight input { width: 11rem; }
.lamp { width: 8px; height: 8px; border-radius: 50%; background: var(--dim); flex: 0 0 auto; }
.lamp.ok { background: var(--ok); }
.lamp.warn { background: var(--warn); }
.lamp.bad { background: var(--bad); }
.state { font-size: 12px; color: var(--dim); white-space: nowrap; }
.state.ok { color: var(--ok); }
.state.warn { color: var(--warn); }
.state.bad { color: var(--bad); }
.notice { border-radius: 8px; padding: 9px 12px; margin: 0 0 14px; font-size: 12.5px; border: 1px solid var(--line); background: var(--card); }
.notice.ok { border-color: color-mix(in srgb, var(--ok) 40%, var(--line)); color: var(--ok); }
.notice.bad { border-color: color-mix(in srgb, var(--bad) 40%, var(--line)); color: var(--bad); }
.notice.warn { border-color: color-mix(in srgb, var(--warn) 40%, var(--line)); color: var(--warn); }
.secret { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; background: var(--track); border-radius: 6px; padding: 8px 10px; overflow-wrap: anywhere; }
.foot { color: var(--dim); font-size: 11.5px; margin-top: 26px; }
table { border-collapse: collapse; width: 100%; font-size: 12px; margin: 6px 0 0; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--divider); vertical-align: top; }
th { color: var(--dim); font-weight: 600; font-size: 10.5px; text-transform: uppercase; letter-spacing: .04em; }
td code { font-size: 11px; }
.tabs { display: flex; gap: 4px; margin: 0 0 16px; flex-wrap: wrap; }
.tabs a { font-size: 12px; color: var(--dim); padding: 3px 9px; border-radius: 999px; background: var(--card); border: 1px solid var(--line); }
.tabs a.on { color: var(--fg); border-color: var(--fg); }
@media (prefers-reduced-motion: reduce) { button:active { transform: none; } }
`
