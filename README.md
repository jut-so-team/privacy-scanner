# Privacy Scanner - DSGVO Compliance Datenerfassung

Ein Python-Tool zur objektiven Erfassung von Tracking-Daten auf Webseiten, vor und nach Consent-Interaktion.

## Features

- **Pre/Post-Consent Vergleich**: Erfasst den Zustand vor und nach dem Klick auf "Alle akzeptieren"
- **Initiator-Tracking**: Zeigt welche Scripts andere Third-Party-Requests auslösen (wie Chrome DevTools)
- **Domain-Aggregation**: Requests werden pro Domain zusammengefasst (LLM-optimiert)
- **Cookie-Analyse**: Alle Cookies mit Attributen (httpOnly, secure, sameSite)
- **Storage-Erfassung**: localStorage und sessionStorage Keys
- **20+ CMP-Anbieter**: OneTrust, Cookiebot, Usercentrics, Didomi, Sourcepoint, und mehr
- **Mehrsprachig**: DE, EN, FR, ES, IT, NL, PL, PT

## Installation

```bash
# Virtuelle Umgebung erstellen & aktivieren
python3 -m venv venv
source venv/bin/activate  # Linux/macOS (Windows: venv\Scripts\activate)

# Dependencies installieren
pip install -r requirements.txt

# Playwright Browser installieren
playwright install chromium
```

**Bei SSL-Fehlern** (häufig auf macOS):
```bash
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

## Verwendung

```bash
# Aktiviere virtuelle Umgebung (falls nicht aktiv)
source venv/bin/activate

# Standard-Scan (kompakt, ~15-20 KB)
python privacy_scanner.py https://example.com

# Detaillierter Scan (alle Einzelrequests, ~200+ KB)
python privacy_scanner.py https://example.com --detailed
```

## Ausgabeformat (Kompakt - Standard)

```json
{
  "scan_meta": {
    "url": "https://example.com",
    "domain": "example.com",
    "scan_timestamp": "2026-02-03T14:30:22.123456+00:00",
    "consent_interaction": {
      "banner_found": true,
      "click_success": true,
      "detected_cmp": "cookiebot"
    }
  },
  "pre_consent": {
    "cookies": [
      { "name": "_ga", "domain": ".example.com", "httpOnly": false, "secure": true }
    ],
    "storage": {
      "localStorage_keys": ["_sp_consent", "user_id"],
      "sessionStorage_keys": []
    },
    "requests": [
      {
        "domain": "google-analytics.com",
        "is_third_party": true,
        "request_count": 5,
        "resource_types": ["script", "xhr"],
        "triggered_by": ["example.com", "googletagmanager.com"]
      }
    ]
  },
  "post_consent": { ... },
  "summary": {
    "pre_consent": {
      "total_cookies": 3,
      "third_party_requests": 12,
      "initiator_chains": {
        "googletagmanager.com": ["google-analytics.com", "facebook.net", "doubleclick.net"]
      }
    }
  }
}
```

## Initiator-Chains verstehen

Das `triggered_by` Feld zeigt, welches Script den Request ausgelöst hat:

```
example.com (Hauptseite)
├── googletagmanager.com (GTM)
│   ├── google-analytics.com
│   ├── facebook.net
│   └── doubleclick.net
├── hotjar.com
│   └── hotjar.io
└── clarity.ms
```

**Initiator-Types:**
- `parser` = Direkt im HTML eingebunden (`<script>`, `<img>`)
- `script` = Durch JavaScript dynamisch nachgeladen

## Unterstützte Consent-Anbieter

Siehe `consent_selectors.py` für die vollständige Liste:

| Anbieter | Status | Anbieter | Status |
|----------|--------|----------|--------|
| OneTrust | ✅ | Borlabs Cookie | ✅ |
| Cookiebot | ✅ | Complianz | ✅ |
| Usercentrics | ✅ | CookieYes | ✅ |
| Didomi | ✅ | iubenda | ✅ |
| TrustArc | ✅ | Klaro | ✅ |
| Quantcast | ✅ | Consentmanager | ✅ |
| Sourcepoint | ✅ | + 10 weitere | ✅ |

## Dateigröße

| Modus | Typische Größe | Verwendung |
|-------|----------------|------------|
| Standard (kompakt) | 15-25 KB | LLM-Analyse, Reports |
| `--detailed` | 150-300 KB | Debugging, Forensik |

## Wartung

Die CSS-Selektoren in `consent_selectors.py` können veralten. Prüfe regelmäßig auf Updates.

## Lizenz

MIT
