package certinfo

import "strings"

// SanitizeField removes Unicode codepoints that have no legitimate use in
// X.509 string fields and that cause problems downstream (log injection,
// Kibana display corruption, Trojan-Source-style bidi attacks). Legitimate
// international text (accents, CJK, Arabic, emoji) is preserved.
//
// Stripped:
//   - U+0000 NUL (the classic CN="example.com\x00evil.com" trick)
//   - C0 controls U+0001..U+001F except TAB (CR/LF strip prevents log
//     injection; cert fields have no legitimate newlines)
//   - U+007F DEL
//   - C1 controls U+0080..U+009F (ANSI escape sequences)
//   - U+200B/200C/200D zero-width space/joiner/non-joiner (Z-WASP)
//   - U+FEFF BOM / zero-width no-break space
//   - U+202A..U+202E bidi explicit overrides (Trojan Source CVE-2021-42574)
//   - U+2066..U+2069 bidi isolates (Trojan Source variant)
//   - U+061C arabic letter mark (bidi control)
//   - U+E0000..U+E007F tag characters (Trojan Source variant)
//
// NOT stripped: U+200E/200F (LTR/RTL marks, milder, used in legit
// multilingual text), regular Unicode letters, punctuation, and emoji.
func SanitizeField(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == 0x00, r == 0x7F:
			return -1
		case r > 0 && r < 0x20 && r != '\t':
			return -1
		case r >= 0x80 && r <= 0x9F:
			return -1
		case r >= 0x200B && r <= 0x200D:
			return -1
		case r == 0xFEFF:
			return -1
		case r >= 0x202A && r <= 0x202E:
			return -1
		case r >= 0x2066 && r <= 0x2069:
			return -1
		case r == 0x061C:
			return -1
		case r >= 0xE0000 && r <= 0xE007F:
			return -1
		}
		return r
	}, s)
}

// SanitizeMultiline is the multi-line sibling of SanitizeField, for text
// blocks such as `openssl x509 -text` output. openssl at its default nameopt
// passes bidi/zero-width codepoints through verbatim, so a hostile CN/SAN can
// carry a Trojan-Source payload that survives HTML escaping and attacks a
// terminal on copy-paste. This strips those while preserving newlines, tabs,
// and legitimate international text.
//
// It is deliberately stricter than SanitizeField (for single structured
// fields): it also strips LRM/RLM (U+200E/F) and the U+2028/U+2029 line and
// paragraph separators, because in a multi-line blob a user may paste into a
// terminal those double as directional/newline injection, whereas a lone
// field keeps LRM/RLM as legitimate directionality.
func SanitizeMultiline(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r < 0x20 || r == 0x7f: // C0 controls + DEL
			return -1
		case r >= 0x80 && r <= 0x9f: // C1 controls
			return -1
		case r == 0x061c: // arabic letter mark
			return -1
		case r >= 0x200b && r <= 0x200f: // ZWSP..ZWJ, LRM, RLM
			return -1
		case r >= 0x202a && r <= 0x202e: // bidi embeddings/overrides
			return -1
		case r >= 0x2066 && r <= 0x2069: // bidi isolates
			return -1
		case r == 0x2028 || r == 0x2029: // line / paragraph separators (act as newlines on paste)
			return -1
		case r == 0xfeff: // BOM / zero-width no-break space
			return -1
		case r >= 0xe0000 && r <= 0xe007f: // tag characters
			return -1
		default:
			return r
		}
	}, s)
}

// SanitizeFields applies SanitizeField to each element and returns the slice.
// It MUTATES ss in place: the caller's backing array is overwritten.
func SanitizeFields(ss []string) []string {
	for i, s := range ss {
		ss[i] = SanitizeField(s)
	}
	return ss
}
