#!/usr/bin/env python3
"""Validate the shared Raiun palette and generate the Desktop theme adapter."""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
TOKENS = ROOT / "design/raiun/tokens.json"
CATALOG = ROOT / "design/raiun/reference.html"
CSS = ROOT / "apps/desktop/desktop-shell/src/raiun-tokens.css"
EMBED = re.compile(r'(<script id="raiun-reference-tokens" type="application/json">)(.*?)(</script>)', re.S)


def luminance(color):
    assert re.fullmatch(r"#[0-9a-fA-F]{6}", color), f"Invalid color: {color}"
    channels = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    values = [c / 12.92 if c <= .04045 else ((c + .055) / 1.055) ** 2.4 for c in channels]
    return sum(c * weight for c, weight in zip(values, (.2126, .7152, .0722)))


def contrast(a, b):
    bright, dark = sorted((luminance(a), luminance(b)), reverse=True)
    return (bright + .05) / (dark + .05)


def validate(tokens):
    assert tokens["version"] == 1
    contract = tokens["contract"]
    assert contract["textMinimumContrast"] >= 4.5
    assert contract["statusTextMinimumContrast"] >= 4.5
    assert contract["controlBorderMinimumContrast"] >= 3
    assert contract["focusMinimumContrast"] >= 3
    assert set(tokens["color"]) == {"light", "dark"}
    assert set(tokens["color"]["light"]) == set(tokens["color"]["dark"])
    checks = []
    for theme, palette in tokens["color"].items():
        for color in palette.values():
            luminance(color)
        for surface in ("canvas", "surface", "inset"):
            for key in ("text", "muted", "success", "warning", "danger", "info"):
                checks.append((f"{theme}/{key}/{surface}", contrast(palette[key], palette[surface]), 4.5))
            for key in ("controlBorder", "focus"):
                checks.append((f"{theme}/{key}/{surface}", contrast(palette[key], palette[surface]), 3))
        for key in ("primary", "primaryHover"):
            checks.append((f"{theme}/onPrimary/{key}", contrast(palette["onPrimary"], palette[key]), 4.5))
    for color in tokens["accountAccent"]:
        checks.append((f"account/{color}/white", contrast(color, "#ffffff"), 4.5))
    for label, value, threshold in checks:
        assert value >= threshold, f"{label}: {value:.4f}:1 < {threshold}:1"
    assert all(isinstance(n, int) and n > 0 for n in tokens["space"])
    assert tokens["space"] == sorted(set(tokens["space"]))
    return checks


def kebab(name):
    return re.sub(r"[A-Z]", lambda m: "-" + m[0].lower(), name)


def theme_block(selector, palette, tokens):
    scheme = "dark" if palette == tokens["color"]["dark"] else "light"
    lines = [f"{selector} {{", f"  color-scheme: {scheme};"]
    lines += [f"  --raiun-{kebab(key)}: {value};" for key, value in palette.items()]
    lines += [f"  --raiun-space-{n}: {n}px;" for n in tokens["space"]]
    lines += [f"  --raiun-radius-{key}: {n}px;" for key, n in tokens["radius"].items()]
    aliases = {"primary": "primary", "primary-dark": "primary-hover", "ink": "text", "text": "text",
               "muted": "muted", "line": "border", "surface": "surface", "subtle": "inset",
               "green": "success", "amber": "warning", "red": "danger"}
    lines += [f"  --{key}: var(--raiun-{value});" for key, value in aliases.items()]
    lines += ["  color: var(--raiun-text);", "  background: var(--raiun-canvas);", "}"]
    return "\n".join(lines)


def generate(tokens):
    light = theme_block(':root, :root[data-theme="light"], :root:not([data-theme])', tokens["color"]["light"], tokens)
    dark = theme_block(':root[data-theme="dark"]', tokens["color"]["dark"], tokens)
    system = theme_block(':root:not([data-theme="light"])', tokens["color"]["dark"], tokens)
    return "/* Generated from design/raiun/tokens.json by scripts/design-tokens.py. */\n" + light + "\n" + dark + "\n@media (prefers-color-scheme: dark) {\n" + system + "\n}\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Regenerate CSS and catalog token embed")
    parser.add_argument("--check", action="store_true", help="Check checked-in consumers (default)")
    args = parser.parse_args()
    tokens = json.loads(TOKENS.read_text())
    checks = validate(tokens)
    catalog = CATALOG.read_text()
    match = EMBED.search(catalog)
    assert match, "Catalog token embed is missing"
    expected = generate(tokens)
    if args.write:
        CSS.write_text(expected)
        CATALOG.write_text(EMBED.sub(lambda m: m[1] + "\n" + json.dumps(tokens, indent=2) + "\n" + m[3], catalog))
    else:
        assert CSS.read_text() == expected, "Desktop token CSS is stale; run design-tokens.py --write"
        assert json.loads(match[2]) == tokens, "Catalog token embed differs from tokens.json"
    print(json.dumps({"result": "pass", "contrastChecks": len(checks),
                      "minimumTextContrast": min(v for k, v, threshold in checks if threshold == 4.5),
                      "minimumControlContrast": min(v for k, v, threshold in checks if threshold == 3),
                      "scope": "token pairs only; runtime and platform accessibility require separate review"}, indent=2))


if __name__ == "__main__":
    main()
