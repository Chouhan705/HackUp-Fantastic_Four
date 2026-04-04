"""Unicode and IDN abuse checks."""
from __future__ import annotations

import logging
import unicodedata

from url_analyzer.models import CheckCategory, Finding, ParsedURL, Severity

logger = logging.getLogger(__name__)

CONFUSABLES: dict[str, list[str]] = {
    'a': ['\u0430', '\u0251', '\u03B1'],      # Cyrillic a, Latin alpha, Greek alpha
    'b': ['\u0432', '\u0253'],                # Cyrillic v, Latin b with hook
    'c': ['\u0441', '\u03F2'],                # Cyrillic s, Greek lunate sigma
    'd': ['\u0501', '\u0257'],                # Coptic d, Latin d with hook
    'e': ['\u0435', '\u0454', '\u03B5'],      # Cyrillic e, Ukrainian ie, Greek epsilon
    'g': ['\u0261'],                          # Latin script small g
    'h': ['\u04BB'],                          # Cyrillic shha
    'i': ['\u0456', '\u04CF', '\u1D0B'],      # Cyrillic i, Cyrillic palochka, small capital I
    'j': ['\u0458'],                          # Cyrillic je
    'k': ['\u03BA'],                          # Greek kappa
    'l': ['\u04CF', '\u217C', '\u1C93'],      # Cyrillic palochka, Roman numeral l, etc
    'm': ['\u217F', '\u1D0D'],                # Roman small m, small capital M
    'n': ['\u0578', '\u03B7'],                # Armenian n, Greek eta
    'o': ['\u03BF', '\u043E', '\u0D20'],      # Greek omicron, Cyrillic o, Malayalam tha
    'p': ['\u0440', '\u03C1'],                # Cyrillic r, Greek rho
    'q': ['\u0566'],                          # Armenian q
    'r': ['\u0433'],                          # Cyrillic ge
    's': ['\u0455', '\u0509'],                # Cyrillic dze, Coptic s
    't': ['\u0442', '\u03C4'],                # Cyrillic te, Greek tau
    'u': ['\u03C5', '\u0446'],                # Greek upsilon, Cyrillic tse
    'v': ['\u03BD', '\u05D8'],                # Greek nu, Hebrew tet
    'w': ['\u0461', '\u051D'],                # Omega, Coptic
    'x': ['\u0445', '\u03C7'],                # Cyrillic ha, Greek chi
    'y': ['\u0443', '\u03B3'],                # Cyrillic u, Greek gamma
    'z': ['\u0225'],                          # Latin z with hook
}


def check_punycode(parsed: ParsedURL) -> Finding | None:
    """Check for IDN punycode in hostname."""
    if "xn--" in parsed.hostname.lower():
        return Finding(
            check="punycode",
            category=CheckCategory.UNICODE,
            severity=Severity.HIGH,
            description="Punycode (IDN) used in hostname",
            evidence=parsed.hostname
        )
    return None


def get_script(char: str) -> str:
    """Determine the script of a character."""
    name = unicodedata.name(char, "").split(" ")[0]
    scripts = {"LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "ARABIC", "HEBREW"}
    if name in scripts:
        return name
    return "OTHER"


def check_mixed_script(parsed: ParsedURL) -> Finding | None:
    """Check for mixed scripts in the hostname."""
    scripts = set()
    for char in parsed.hostname:
        if char.isalpha():
            scripts.add(get_script(char))
            
    if len(scripts) >= 2:
        return Finding(
            check="mixed_script",
            category=CheckCategory.UNICODE,
            severity=Severity.CRITICAL,
            description="Multiple scripts mixed in hostname",
            evidence=", ".join(sorted(scripts))
        )
    return None


def check_confusable_chars(parsed: ParsedURL) -> Finding | None:
    """Check for confusable characters in hostname."""
    # Build reverse map for fast lookup
    reverse_map = {confus: ascii_char for ascii_char, confs in CONFUSABLES.items() for confus in confs}
    
    for char in parsed.hostname:
        if char in reverse_map:
            return Finding(
                check="confusable_chars",
                category=CheckCategory.UNICODE,
                severity=Severity.CRITICAL,
                description="Confusable homograph character found",
                evidence=f"U+{ord(char):04X} looks like '{reverse_map[char]}'"
            )
    return None


def run_all(parsed: ParsedURL) -> list[Finding]:
    """Run all unicode checks."""
    checks = [
        check_punycode,
        check_mixed_script,
        check_confusable_chars
    ]
    findings = []
    for check in checks:
        if result := check(parsed):
            findings.append(result)
    return findings
