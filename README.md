# Persönliche Finanzen — MVP v1.0

Web-Anwendung zur zentralen Verwaltung von Verbindlichkeiten, Einkünften, Ausgaben, Investments und Aktienplänen. Vollständig client-seitig, **alle Daten verschlüsselt im Browser** (AES-GCM, Schlüssel aus PIN via PBKDF2). Kein Server, kein Cloud-Backend.

## Erster Start

1. URL öffnen
2. Beim **ersten Mal**: 6-stelligen PIN festlegen (wird gleich zweimal abgefragt). Diese PIN ist gleichzeitig der Verschlüsselungs-Schlüssel deiner Daten.
3. Optional: Demo-Daten laden, um die App zu erkunden
4. **Wichtig:** Über `⋯` → „Verschlüsseltes Backup" regelmässig sichern. **Ohne PIN UND ohne Backup sind die Daten unwiderruflich verloren.**

## Funktionsumfang

### Modul 1 – Zugang (F-Z-01 bis F-Z-11)
- 6-stelliger PIN-Login mit Klemmen-/Verstecken-Eingabe
- PIN-Hash via PBKDF2 (150’000 Iter.) + AES-GCM 256-Bit
- Brute-Force-Schutz: 5 Fehlversuche → 15 Min. Lock
- Auto-Logout nach 15 Min. Inaktivität (konfigurierbar)
- PIN-Wechsel mit Re-Verschlüsselung aller Daten
- Recovery: Backup-Datei mit alter PIN wiederherstellbar

### Modul 2 – Kurzfristige Verbindlichkeiten (F-KV-01 bis F-KV-08)
- CRUD, Kategorien (Kreditkarte, Steuern, Rechnung …)
- Filter nach Kategorie/Status, Volltext-Suche
- Fälligkeits-Farbcodierung (rot < 7 Tage, gelb < 14 Tage)
- Teilrückzahlungen erfassbar
- Jährliche Zinslast wird berechnet
- CSV-Export

### Modul 3 – Langfristige Verbindlichkeiten (F-LV-01 bis F-LV-07)
- Hypothek / Konsumkredit / Leasing / Studiendarlehen
- Automatische Zinslast-Berechnung (mtl. + jährl.)
- Hinweis 90 Tage vor Vertragsende
- Sondertilgungen erfassbar
- CSV-Export

### Modul 4 – Einkünfte (F-E-01 bis F-E-05)
- Lohn / Bonus / Miete / Dividende / Rente etc.
- Frequenz-Faktor (monatl/quart./halbj./jährl./einmalig)
- Automatische Hochrechnung Ø/Monat
- Filter + Suche + CSV

### Modul 5 – Ausgaben (F-A-01 bis F-A-07)
- 9 Kategorien (Wohnen, Versicherung, Abo, Lebenshaltung, Mobilität …)
- Fix / Variabel Klassifizierung
- Automatische Mtl-Hochrechnung
- Zahlungsmethode (Dauerauftrag, LSV, Kreditkarte …)
- Filter + Suche + CSV

### Modul 6 – Investments (F-I-01 bis F-I-09)
- Aktien / ETF / Fonds / Anleihen / Krypto / Säule 3a / Cash
- Anzahl × Kurs → Marktwert
- Gewinn/Verlust in CHF und %
- Transaktionshistorie (Käufe, Verkäufe, Dividenden)
- Portfolio-Allokation als Ring-Diagramm im Dashboard
- CSV-Export

### Modul 7 – Aktienpläne (F-AP-01 bis F-AP-11)
- RSU / PSU / Option / ESPP / Restricted Shares
- Automatische Vesting-Berechnung (Jahre, Cliff, Rhythmus)
- Vesting-Timeline mit Tranchen-Kacheln
- Hinweise: bevorstehende Vesting-Tranchen (90 Tage)
- Aktueller Wert (gevestet) × Kurs
- Konzentrationsrisiko gegen Limit (Default 30 %)
- Ereignisse (Ausübung, Verkauf, Vesting) erfassbar

### Übergreifend (F-U-01 bis F-U-06)
- Dashboard mit Kennzahlen:
  - Netto-Vermögen
  - Monatlicher Cashflow
  - Sparquote (%)
  - Schuldendienst-Quote
  - Anstehende Fälligkeiten (30 T)
  - Bevorstehende Vesting-Tranchen (90 T)
  - Einkünfte/Ausgaben nach Kategorie
  - Portfolio-Allokation (Ring)
- Globale Suche (Strg/Cmd+K)
- Verschlüsseltes Backup als JSON (.json mit AES-Daten)
- CSV-Export pro Modul

## Sicherheit

- **At-Rest-Verschlüsselung**: alle Datenblöcke (kv, lv, einkünfte, ausgaben, investments, aktienpläne) werden mit AES-256-GCM verschlüsselt im `localStorage` abgelegt
- **Schlüssel-Ableitung**: PBKDF2 (SHA-256, 150’000 Iterationen) aus 6-stelligem PIN + 16-Byte Zufalls-Salt
- **PIN-Verifikation**: Versuch der Entschlüsselung eines bekannten Magic-Strings — kein Klartext-Hash auf der Disk
- **PIN niemals im Klartext**, niemals an einen Server gesendet (keiner vorhanden)
- **Brute-Force**: 5 Fehlversuche → 15 Min. Lock (im `localStorage` getrackt)
- **Hinweis zur PIN-Schwäche**: 6 Ziffern = 10⁶ Kombinationen. Bei vollständigem Lese-Zugriff auf den `localStorage` und der Anwendung lässt sich offline durch-rechnen. PBKDF2-Iterationen + Browser-Bindung machen das langsam, aber nicht unmöglich. Für maximale Sicherheit: PIN aus 6 zufälligen Ziffern wählen UND Backup-Datei separat aufbewahren.

## Datenhaltung

- **Single-Device**: Daten liegen nur in dem Browser, in dem die App geladen wurde
- Cache löschen / neuer Browser = Daten weg (PIN auch)
- **Backup ist Pflicht** — JSON kann auf jedem anderen Gerät mit der ursprünglichen PIN wieder eingespielt werden

## Tech-Stack

Vanilla HTML / CSS / JS, Web Crypto API. Keine externen Abhängigkeiten, kein Build-Step.

## Was im MVP **nicht** umgesetzt ist (laut Lastenheft)

- 2FA TOTP (F-Z-05) → SOLL
- Geräte-Erkennung mit E-Mail-Bestätigung (F-Z-06) → SOLL
- Audit-Log-Persistenz (F-Z-10) → SOLL
- Automatische Kurs-API-Anbindung (F-I-05) → SOLL — Kurse manuell pflegen
- Open Banking / PSD2 → KANN, ausserhalb MVP
- Cloud-Hosting in CH/EU → entfällt da kein Server (alles lokal)
