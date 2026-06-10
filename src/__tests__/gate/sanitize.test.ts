import { describe, expect, test } from "bun:test";
import { stripControlChars } from "../../gate/sanitize.ts";

const ch = (code: number) => String.fromCharCode(code);

describe("stripControlChars", () => {
  test("replaces C0 control characters (NUL through 0x1f) with spaces", () => {
    expect(stripControlChars(`a${ch(0x00)}bc`)).toBe("a bc");
    expect(stripControlChars("line1\nline2\tcol")).toBe("line1 line2 col");
    // ESC (0x1b) introducing an ANSI color sequence must be neutralized.
    expect(stripControlChars(`${ch(0x1b)}[31mred${ch(0x1b)}[0m`)).toBe(" [31mred [0m");
  });

  test("replaces DEL (0x7f) with a space", () => {
    expect(stripControlChars(`a${ch(0x7f)}b`)).toBe("a b");
  });

  test("replaces C1 control characters (0x80 through 0x9f) with spaces", () => {
    // U+009B is the single-byte CSI (Control Sequence Introducer) — a terminal
    // on a Latin-1/8-bit code path can act on it like ESC-[ to redraw output.
    expect(stripControlChars(`a${ch(0x9b)}b`)).toBe("a b");
    // Boundaries of the C1 range plus a representative middle code point.
    expect(stripControlChars(`${ch(0x80)}${ch(0x90)}${ch(0x9f)}`)).toBe("   ");
  });

  test("preserves printable ASCII and ordinary Unicode (>= U+00A0)", () => {
    expect(stripControlChars("café — 日本 🎉")).toBe("café — 日本 🎉");
    expect(stripControlChars("normal text 123")).toBe("normal text 123");
    // U+00A0 (non-breaking space) is the first code point above the C1 range.
    expect(stripControlChars(`a${ch(0xa0)}b`)).toBe(`a${ch(0xa0)}b`);
  });
});
