# Hash Identifier

Kleines CLI-Tool, das Hash-Strings erkennt und verständlich erklärt — auf Deutsch, mit klarer Konfidenz (Trefferwahrscheinlichkeit, nicht kryptografische Sicherheit).

Ideal fürs Lernen, CTFs, Forensik-First-Pass und Portfolio.

## Features

- **Viele Formate:** Hex-Digests (MD5, NTLM, SHA-1/2/3, BLAKE2, …), bcrypt, Argon2, scrypt, yescrypt, Linux Crypt (`$5$`/`$6$`), Django, WordPress/PHPass, Drupal, MySQL, LDAP `{SSHA}`, Cisco Type 4/8/9, Base64-Längen, Fingerprints mit `:`/Leerzeichen
- **Idiotensichere Ausgabe:** Eingabe → Kurzinfo → „Am ehesten“ → ggf. alle Kandidaten
- **Konfidenz HOCH / MITTEL / NIEDRIG** plus kurze Erklärung, wofür der Hash typisch ist
- **Keine Abhängigkeiten** — nur Python 3 Standardbibliothek

## Voraussetzungen

- Python 3.9+ (getestet mit 3.x)

## Nutzung

```bash
# Interaktiv
python3 hash_identifier.py

# Direkt als Argument
python3 hash_identifier.py '5d41402abc4b2a76b9719d911017c592'
python3 hash_identifier.py '$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
```

### Beispielausgabe (gekürzt)

```
════════════════════════════════════════════════════════════════
  HASH-IDENTIFIER — Analyse
════════════════════════════════════════════════════════════════

  Eingabe:
    5d41402abc4b2a76b9719d911017c592

  → Am ehesten:  MD5
    Kategorie:   Hex-Digest
    Konfidenz:   HOCH    — sehr wahrscheinlich
    Bedeutung:   Sehr verbreitet: Datei-Checksummen, alte Passwörter
```

## Hinweis zur Erkennung

Reine Hex-Hashes **ohne Präfix** (z. B. 32 Zeichen) lassen sich nicht zu 100 % einem Algorithmus zuordnen — gleiche Länge bedeutet oft mehrere Kandidaten (z. B. MD5 **und** NTLM).  
**Konfidenz** meint immer die Trefferwahrscheinlichkeit der Erkennung, nicht ob der Algorithmus kryptografisch sicher ist (MD5 ist gebrochen, kann aber trotzdem klar erkannt werden).

## Projektstruktur

```
mein-hash-identifier/
├── hash_identifier.py   # gesamtes Tool
└── README.md
```

## Lizenz

MIT — frei zum Lernen, Teilen und Weiterbauen.
