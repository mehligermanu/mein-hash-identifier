#!/usr/bin/env python3
"""Hash-Identifier: erkennt gängige Hash-Formate und erklärt sie verständlich."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Match:
    name: str
    confidence: str  # hoch | mittel | niedrig
    category: str
    note: str


# Hex-Längen → (Name, Confidence, Erklärung)
HEX_BY_LENGTH: dict[int, list[tuple[str, str, str]]] = {
    8: [
        ("CRC32", "mittel", "Prüfsumme (Dateien, Netzwerke)"),
        ("Adler-32", "niedrig", "Prüfsumme (zlib)"),
    ],
    16: [
        ("MySQL 3.x (OLD_PASSWORD)", "mittel", "Alte MySQL-Passwort-Hashes"),
        ("Half MD5", "niedrig", "Gekürzter MD5"),
    ],
    32: [
        ("MD5", "hoch", "Sehr verbreitet: Datei-Checksummen, alte Passwörter"),
        ("NTLM", "hoch", "Windows-Passwort-Hash (ohne Salt)"),
        ("MD4", "mittel", "Vorgänger von MD5, selten allein"),
    ],
    40: [
        ("SHA-1", "hoch", "Git-Commits, ältere Zertifikate, Datei-Hashes"),
        ("RIPEMD-160", "mittel", "u. a. intern bei Bitcoin-Adressen"),
        ("MySQL 4.1+ (ohne *)", "mittel", "MySQL PASSWORD() oft mit * davor"),
    ],
    56: [
        ("SHA-224", "hoch", "SHA-2-Familie"),
        ("SHA3-224", "mittel", "SHA-3-Familie"),
    ],
    64: [
        ("SHA-256", "hoch", "Sehr verbreitet: Dateien, TLS, Blockchain"),
        ("SHA3-256", "mittel", "SHA-3-Variante"),
        ("BLAKE2s", "mittel", "Schneller Hash (z. B. Argon2-intern)"),
    ],
    96: [
        ("SHA-384", "hoch", "SHA-2-Familie"),
        ("SHA3-384", "mittel", "SHA-3-Familie"),
    ],
    128: [
        ("SHA-512", "hoch", "SHA-2-Familie, oft bei Datei-Hashes"),
        ("SHA3-512", "mittel", "SHA-3-Familie"),
        ("BLAKE2b", "mittel", "Schneller Hash (z. B. libsodium)"),
        ("Whirlpool", "niedrig", "Älterer kryptografischer Hash"),
    ],
}


# (Name, Confidence, Kategorie, Erklärung, Regex) — erste passende klare Regel gewinnt
PREFIX_RULES: list[tuple[str, str, str, str, re.Pattern[str]]] = [
    (
        "bcrypt",
        "hoch",
        "Passwort-Hash",
        "Moderne Passwort-Speicherung. Die Zahl nach $2a$/$2b$/$2y$ ist der Kostenfaktor.",
        re.compile(r"^\$2[abyxy]\$\d{2}\$[./A-Za-z0-9]{53}$"),
    ),
    (
        "bcrypt (Format unvollständig)",
        "mittel",
        "Passwort-Hash",
        "Beginnt wie bcrypt, Länge/Zeichen aber ungewöhnlich — Eingabe prüfen.",
        re.compile(r"^\$2[abyxy]\$"),
    ),
    (
        "Argon2id",
        "hoch",
        "Passwort-Hash",
        "Empfohlener moderner Passwort-Hash (OWASP). Sehr resistent gegen GPU-Angriffe.",
        re.compile(r"^\$argon2id\$"),
    ),
    (
        "Argon2i",
        "hoch",
        "Passwort-Hash",
        "Argon2-Variante (side-channel-resistent). Oft in PHP/libsodium.",
        re.compile(r"^\$argon2i\$"),
    ),
    (
        "Argon2d",
        "hoch",
        "Passwort-Hash",
        "Argon2-Variante (datenabhängig). Seltener für Passwörter.",
        re.compile(r"^\$argon2d\$"),
    ),
    (
        "scrypt",
        "hoch",
        "Passwort-Hash",
        "Speicherintensiver Passwort-Hash ($scrypt$).",
        re.compile(r"^\$scrypt\$"),
    ),
    (
        "yescrypt",
        "hoch",
        "Passwort-Hash",
        "Moderner Linux-/Unix-Passwort-Hash (in manchen Distros Standard).",
        re.compile(r"^\$y\$"),
    ),
    (
        "SHA-512 Crypt",
        "hoch",
        "Passwort-Hash",
        "Klassischer Linux-Passwort-Hash ($6$ in /etc/shadow).",
        re.compile(r"^\$6\$"),
    ),
    (
        "SHA-256 Crypt",
        "hoch",
        "Passwort-Hash",
        "Linux-Passwort-Hash ($5$ in /etc/shadow).",
        re.compile(r"^\$5\$"),
    ),
    (
        "apr1 (Apache MD5)",
        "hoch",
        "Passwort-Hash",
        "Apache htpasswd MD5-Variante ($apr1$).",
        re.compile(r"^\$apr1\$"),
    ),
    (
        "MD5 Crypt",
        "hoch",
        "Passwort-Hash",
        "Alter Unix-Passwort-Hash ($1$). Veraltet, aber noch anzutreffen.",
        re.compile(r"^\$1\$"),
    ),
    (
        "PBKDF2 (Django)",
        "hoch",
        "Passwort-Hash",
        "Django-Passwort-Hash (pbkdf2_sha256 / pbkdf2_sha1).",
        re.compile(r"^pbkdf2_sha(256|1)\$"),
    ),
    (
        "bcrypt (Django)",
        "hoch",
        "Passwort-Hash",
        "Django bcrypt-Hash.",
        re.compile(r"^bcrypt(_sha256)?\$"),
    ),
    (
        "Argon2 (Django)",
        "hoch",
        "Passwort-Hash",
        "Django Argon2-Hash.",
        re.compile(r"^argon2\$"),
    ),
    (
        "scrypt (Django)",
        "hoch",
        "Passwort-Hash",
        "Django scrypt-Hash.",
        re.compile(r"^scrypt\$"),
    ),
    (
        "PHPass / WordPress",
        "hoch",
        "Passwort-Hash",
        "WordPress, phpBB und ähnliche PHP-Apps ($P$ / $H$).",
        re.compile(r"^\$[PH]\$[./A-Za-z0-9]{31}$"),
    ),
    (
        "PHPass / WordPress (ähnlich)",
        "mittel",
        "Passwort-Hash",
        "Beginnt mit $P$/$H$, Länge ungewöhnlich.",
        re.compile(r"^\$[PH]\$"),
    ),
    (
        "Drupal 7+",
        "hoch",
        "Passwort-Hash",
        "Drupal-Passwort-Hash ($S$).",
        re.compile(r"^\$S\$[./A-Za-z0-9]{52}$"),
    ),
    (
        "Drupal 7+ (ähnlich)",
        "mittel",
        "Passwort-Hash",
        "Beginnt mit $S$, Länge ungewöhnlich.",
        re.compile(r"^\$S\$"),
    ),
    (
        "LDAP {SSHA}",
        "hoch",
        "Passwort-Hash",
        "LDAP Salted SHA-1 (meist Base64 nach dem Präfix).",
        re.compile(r"^\{SSHA\}", re.IGNORECASE),
    ),
    (
        "LDAP {SHA}",
        "hoch",
        "Passwort-Hash",
        "LDAP SHA-1 (Base64).",
        re.compile(r"^\{SHA\}", re.IGNORECASE),
    ),
    (
        "LDAP {SMD5}",
        "hoch",
        "Passwort-Hash",
        "LDAP Salted MD5 (Base64).",
        re.compile(r"^\{SMD5\}", re.IGNORECASE),
    ),
    (
        "LDAP {MD5}",
        "hoch",
        "Passwort-Hash",
        "LDAP MD5 (Base64).",
        re.compile(r"^\{MD5\}", re.IGNORECASE),
    ),
    (
        "MySQL 4.1+ PASSWORD()",
        "hoch",
        "Passwort-Hash",
        "MySQL-Passwort: Stern (*) + 40 Hex-Zeichen.",
        re.compile(r"^\*[0-9A-Fa-f]{40}$"),
    ),
    (
        "Cisco Type 8 (PBKDF2)",
        "hoch",
        "Passwort-Hash",
        "Cisco Type-8 (PBKDF2-SHA256).",
        re.compile(r"^\$8\$"),
    ),
    (
        "Cisco Type 9 (scrypt)",
        "hoch",
        "Passwort-Hash",
        "Cisco Type-9 (scrypt).",
        re.compile(r"^\$9\$"),
    ),
    (
        "Cisco Type 4",
        "mittel",
        "Passwort-Hash",
        "Cisco Type-4 (SHA-256).",
        re.compile(r"^\$4\$"),
    ),
    (
        "md5crypt",
        "mittel",
        "Passwort-Hash",
        "MD5-basiertes Crypt-Format ($md5$).",
        re.compile(r"^\$md5\$"),
    ),
]


def is_hex(text: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", text))


def is_base64ish(text: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+=*", text)) and len(text) >= 16


def _matches_prefix(s: str) -> list[Match]:
    """Erste passende Regel(n). Exakte Treffer stoppen; 'ähnlich'-Regeln nur als Fallback."""
    found: list[Match] = []
    for name, conf, cat, note, pattern in PREFIX_RULES:
        if not pattern.match(s):
            continue
        # Wenn schon ein genauer Treffer da ist, "ähnlich/unvollständig" überspringen
        if ("unvollständig" in name or "ähnlich" in name) and found:
            continue
        found.append(Match(name, conf, cat, note))
        # Klarer Modular-Crypt / Framework / LDAP-Treffer: genug
        if conf == "hoch" and not ("unvollständig" in name or "ähnlich" in name):
            break
    return found


def _matches_hex(s: str) -> list[Match]:
    length = len(s)
    if length in HEX_BY_LENGTH:
        return [
            Match(name, conf, "Hex-Digest", note)
            for name, conf, note in HEX_BY_LENGTH[length]
        ]
    return [
        Match(
            f"Unbekannter Hex-String ({length} Zeichen)",
            "niedrig",
            "Unklar",
            "Sieht nach Hex aus, Länge passt zu keinem Standard-Hash.",
        )
    ]


def _matches_base64(s: str) -> list[Match]:
    pad = s.count("=")
    approx_bytes = (len(s) * 3) // 4 - pad
    guess = {
        16: ("MD5 (Base64)", "Passt zur Länge von MD5 als Base64."),
        20: ("SHA-1 (Base64)", "Passt zur Länge von SHA-1 als Base64."),
        28: ("SHA-224 (Base64)", "Passt zur Länge von SHA-224 als Base64."),
        32: ("SHA-256 / BLAKE2s (Base64)", "Passt zur Länge von 32-Byte-Hashes als Base64."),
        48: ("SHA-384 (Base64)", "Passt zur Länge von SHA-384 als Base64."),
        64: ("SHA-512 / BLAKE2b (Base64)", "Passt zur Länge von 64-Byte-Hashes als Base64."),
    }
    if approx_bytes in guess:
        name, note = guess[approx_bytes]
        return [Match(name, "mittel", "Base64-Digest", note)]
    return [
        Match(
            f"Base64-ähnlich (~{approx_bytes} Bytes)",
            "niedrig",
            "Unklar",
            "Könnte ein kodierter Hash oder etwas anderes sein.",
        )
    ]


def identify_hash(raw: str) -> list[Match]:
    s = raw.strip()
    if not s:
        return []

    # 1) Präfixe / bekannte Formate
    prefix = _matches_prefix(s)
    if prefix:
        return prefix

    # 2) Reines Hex
    if is_hex(s):
        return _matches_hex(s)

    # 3) Hex mit Leerzeichen oder Doppelpunkten (Fingerprints)
    cleaned = re.sub(r"[\s:]", "", s)
    if cleaned != s and is_hex(cleaned):
        return [
            Match(
                m.name + " (Trennzeichen entfernt)",
                m.confidence,
                m.category,
                m.note,
            )
            for m in _matches_hex(cleaned)
        ]

    # 4) Base64-Länge als Notnagel
    if is_base64ish(s):
        return _matches_base64(s)

    return [
        Match(
            "Nicht erkannt",
            "niedrig",
            "Unklar",
            "Kein bekanntes Hash-Muster. Prüfe Copy-Paste, Anführungszeichen oder Leerzeichen.",
        )
    ]


CONF_LABEL = {
    "hoch": "HOCH    — sehr wahrscheinlich",
    "mittel": "MITTEL  — möglich, Kontext prüfen",
    "niedrig": "NIEDRIG — nur ein Hinweis",
}

CONF_ORDER = {"hoch": 0, "mittel": 1, "niedrig": 2}


def _bar(char: str = "─", width: int = 64) -> str:
    return char * width


def print_report(raw: str, matches: list[Match]) -> None:
    s = raw.strip()
    print()
    print(_bar("═"))
    print("  HASH-IDENTIFIER — Analyse")
    print(_bar("═"))
    print()
    print("  Eingabe:")
    display = s if len(s) <= 72 else s[:72] + "…"
    print(f"    {display}")
    if len(s) > 72:
        print(f"    (gesamt {len(s)} Zeichen)")
    print()
    print("  Kurzinfo:")
    print(f"    Zeichenlänge : {len(s)}")
    print(f"    Nur Hex?     : {'ja' if is_hex(s) else 'nein'}")
    print(f"    Nur Base64?  : {'ja' if is_base64ish(s) and not is_hex(s) else 'nein'}")
    print()

    if not s:
        print("  Ergebnis: LEER — bitte einen Hash einfügen.")
        print(_bar("═"))
        print()
        return

    ranked = sorted(matches, key=lambda m: CONF_ORDER.get(m.confidence, 9))
    best = ranked[0]

    print(_bar())
    print("  ERGEBNIS (einfach gesagt)")
    print(_bar())
    print()
    if best.name == "Nicht erkannt":
        print("  → Das sieht nicht nach einem bekannten Hash aus.")
        print(f"    Tipp: {best.note}")
    else:
        print(f"  → Am ehesten:  {best.name}")
        print(f"    Kategorie:   {best.category}")
        print(f"    Konfidenz:   {CONF_LABEL[best.confidence]}")
        print(f"    Bedeutung:   {best.note}")
    print()

    if len(ranked) > 1:
        print(_bar())
        print("  ALLE MÖGLICHEN TREFFER")
        print(_bar())
        print()
        for i, m in enumerate(ranked, 1):
            marker = "★" if i == 1 else "·"
            print(f"  {marker} {i}. {m.name}")
            print(f"       Kategorie : {m.category}")
            print(f"       Konfidenz  : {CONF_LABEL[m.confidence]}")
            print(f"       Hinweis   : {m.note}")
            print()

    print(_bar())
    print("  Lesehilfe")
    print(_bar())
    print("  • Konfidenz = Trefferwahrscheinlichkeit (nicht kryptografische")
    print("    Sicherheit!). MD5 kann „HOCH“ matchen und trotzdem gebrochen sein.")
    print("  • HOCH    = Format passt klar → Erkennung sehr wahrscheinlich.")
    print("  • MITTEL  = mehrere Algorithmen möglich → Kontext nötig.")
    print("  • NIEDRIG = nur Länge/Aussehen → oft unsicher.")
    print("  • Reine Hex-Hashes (MD5/SHA/…) ohne Präfix sind nicht")
    print("    100 % unterscheidbar — gleiche Länge = gleiche Kandidaten.")
    print()
    print(_bar("═"))
    print()


def main() -> None:
    if len(sys.argv) > 1:
        target = " ".join(sys.argv[1:])
    else:
        try:
            target = input("Hash einfügen (Enter): ")
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

    print_report(target, identify_hash(target))


if __name__ == "__main__":
    main()
