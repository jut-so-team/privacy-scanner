#!/usr/bin/env python3
"""
Privacy Scanner - DSGVO Compliance Datenerfassung

Scannt eine URL und erfasst objektive technische Daten über das
Tracking-Verhalten vor und nach Consent-Interaktion.

Ausgabe: JSON-Datei mit allen erfassten Datenpunkten.

Verwendung:
    python privacy_scanner.py https://example.com
"""

import sys
import json
import re
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse
from pathlib import Path
from typing import Any

from playwright.sync_api import (
    sync_playwright,
    Page,
    BrowserContext,
    Request,
    Response,
    CDPSession,
    TimeoutError as PlaywrightTimeout,
)
import tldextract

from consent_selectors import (
    CMP_ACCEPT_SELECTORS,
    BANNER_CONTAINER_SELECTORS,
    get_all_accept_selectors,
    get_all_accept_texts,
)


# =============================================================================
# KONFIGURATION
# =============================================================================

class ScanConfig:
    """Zentrale Konfiguration für den Scanner."""
    
    # Timeouts (in Millisekunden)
    PAGE_LOAD_TIMEOUT = 30_000       # Max. Wartezeit für Seitenladung
    BANNER_SEARCH_TIMEOUT = 5_000    # Max. Wartezeit für Banner-Suche
    POST_CONSENT_WAIT = 5_000        # Wartezeit nach Consent-Klick (ms)
    NETWORK_IDLE_TIMEOUT = 10_000    # Wartezeit für Network Idle
    
    # Request-Typen die erfasst werden (DSGVO-relevant)
    RELEVANT_RESOURCE_TYPES = {
        "document",     # HTML-Dokumente
        "script",       # JavaScript (Tracker, Analytics)
        "xhr",          # AJAX-Requests
        "fetch",        # Fetch API Requests
        "image",        # Bilder (Tracking-Pixel!)
        "ping",         # Beacon/Ping Requests
        "websocket",    # WebSocket-Verbindungen
        "other",        # Sonstiges (oft Beacons)
    }
    
    # Request-Typen die ignoriert werden
    IGNORED_RESOURCE_TYPES = {
        "stylesheet",   # CSS
        "font",         # Schriften
        "media",        # Video/Audio
        "manifest",     # Web App Manifest
        "texttrack",    # Untertitel
    }


# =============================================================================
# BEKANNTE TRACKING-DOMAINS (für Referenz/Kategorisierung)
# =============================================================================

KNOWN_TRACKING_CATEGORIES = {
    "analytics": [
        "google-analytics.com",
        "googletagmanager.com",
        "analytics.google.com",
        "matomo.cloud",
        "piwik.pro",
        "hotjar.com",
        "mouseflow.com",
        "clarity.ms",
        "plausible.io",
        "mixpanel.com",
        "amplitude.com",
        "segment.io",
        "segment.com",
        "heap.io",
        "fullstory.com",
        "logrocket.com",
        "smartlook.com",
    ],
    "advertising": [
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "google.com/pagead",
        "facebook.net",
        "facebook.com/tr",
        "connect.facebook.net",
        "ads.linkedin.com",
        "linkedin.com/px",
        "ads.twitter.com",
        "t.co",
        "amazon-adsystem.com",
        "criteo.com",
        "criteo.net",
        "outbrain.com",
        "taboola.com",
        "adnxs.com",
        "adsrvr.org",
        "pubmatic.com",
        "rubiconproject.com",
        "openx.net",
        "teads.tv",
    ],
    "social_plugins": [
        "platform.twitter.com",
        "platform.linkedin.com",
        "apis.google.com",
        "connect.facebook.net",
    ],
    "tag_managers": [
        "googletagmanager.com",
        "tagmanager.google.com",
        "tags.tiqcdn.com",
        "cdn.segment.com",
    ],
    "consent_management": [
        "cookiebot.com",
        "onetrust.com",
        "cookielaw.org",
        "usercentrics.eu",
        "didomi.io",
        "trustarc.com",
        "quantcast.com",
        "consentmanager.net",
        "iubenda.com",
        "osano.com",
        "termly.io",
    ],
    "customer_data_platform": [
        "segment.io",
        "rudderstack.com",
        "mparticle.com",
    ],
    "session_replay": [
        "hotjar.com",
        "clarity.ms",
        "mouseflow.com",
        "fullstory.com",
        "logrocket.com",
        "smartlook.com",
        "rrweb.io",
    ],
    "ab_testing": [
        "optimizely.com",
        "vwo.com",
        "abtasty.com",
        "kameleoon.com",
    ],
    "fingerprinting": [
        "fingerprintjs.com",
        "fpjs.io",
    ],
}


# =============================================================================
# DATENERFASSUNG
# =============================================================================

class DataCollector:
    """Sammelt alle Request/Response-Daten während des Scans."""
    
    # Mapping von CDP resource types zu lesbaren Namen
    CDP_RESOURCE_TYPES = {
        "Document": "document",
        "Script": "script",
        "XHR": "xhr",
        "Fetch": "fetch",
        "Image": "image",
        "Ping": "ping",
        "WebSocket": "websocket",
        "Other": "other",
        "Stylesheet": "stylesheet",
        "Font": "font",
        "Media": "media",
    }
    
    def __init__(self, site_domain: str):
        self.site_domain = site_domain
        self.requests: list[dict] = []
        self.responses: dict[str, dict] = {}  # URL -> Response-Daten
        self.websockets: list[dict] = []
        self._request_id = 0
        self._seen_urls: set[str] = set()  # Verhindere Duplikate
    
    def _extract_initiator_info(self, initiator: dict) -> dict | None:
        """Extrahiert lesbare Initiator-Informationen aus CDP-Daten."""
        if not initiator:
            return None
        
        initiator_type = initiator.get("type", "unknown")
        
        result = {
            "type": initiator_type,  # script, parser, preload, preflight, other
        }
        
        # URL des auslösenden Scripts
        if "url" in initiator:
            result["url"] = initiator["url"]
            # Extrahiere base_domain des Initiators
            extracted = tldextract.extract(initiator["url"])
            result["base_domain"] = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        
        # Line number im auslösenden Script
        if "lineNumber" in initiator:
            result["line"] = initiator["lineNumber"]
        
        # Stack Trace (wenn vorhanden) - zeigt die Aufrufkette
        if "stack" in initiator and initiator["stack"].get("callFrames"):
            call_frames = initiator["stack"]["callFrames"]
            stack_summary = []
            
            for frame in call_frames[:5]:  # Max 5 Frames
                frame_info = {
                    "function": frame.get("functionName", "(anonymous)"),
                }
                if frame.get("url"):
                    frame_info["url"] = frame["url"]
                    extracted = tldextract.extract(frame["url"])
                    frame_info["base_domain"] = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
                if frame.get("lineNumber"):
                    frame_info["line"] = frame["lineNumber"]
                stack_summary.append(frame_info)
            
            if stack_summary:
                result["stack"] = stack_summary
                # Der erste Frame mit Domain ist der direkte Auslöser
                for frame in stack_summary:
                    if frame.get("base_domain"):
                        result["triggered_by_domain"] = frame["base_domain"]
                        break
        
        return result
    
    def handle_cdp_request(self, params: dict) -> None:
        """Erfasst Request direkt von CDP mit vollständigen Initiator-Daten."""
        request_data = params.get("request", {})
        initiator = params.get("initiator", {})
        url = request_data.get("url", "")
        
        if not url:
            return
        
        # Verhindere Duplikate
        if url in self._seen_urls:
            return
        self._seen_urls.add(url)
        
        # Resource Type von CDP
        cdp_type = params.get("type", "Other")
        resource_type = self.CDP_RESOURCE_TYPES.get(cdp_type, cdp_type.lower())
        
        # Filtere irrelevante Typen
        if resource_type in ScanConfig.IGNORED_RESOURCE_TYPES:
            return
        
        if resource_type not in ScanConfig.RELEVANT_RESOURCE_TYPES:
            return
        
        extracted = tldextract.extract(url)
        base_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        
        # Prüfe ob First-Party oder Third-Party
        is_third_party = base_domain != self.site_domain
        
        self._request_id += 1
        
        result = {
            "id": self._request_id,
            "url": url,
            "base_domain": base_domain,
            "resource_type": resource_type,
            "method": request_data.get("method", "GET"),
            "is_third_party": is_third_party,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        # Initiator-Informationen
        initiator_info = self._extract_initiator_info(initiator)
        if initiator_info:
            result["initiator"] = initiator_info
        
        # POST-Daten
        if request_data.get("postData"):
            post_data = request_data["postData"]
            if len(post_data) > 500:
                result["post_data_preview"] = post_data[:500] + "..."
                result["post_data_hash"] = hashlib.md5(post_data.encode()).hexdigest()
            else:
                result["post_data"] = post_data
        
        # Wichtige Headers
        headers = request_data.get("headers", {})
        important_headers = {}
        for key in ["Referer", "Origin", "Cookie", "User-Agent"]:
            if key in headers:
                important_headers[key.lower()] = headers[key]
        if important_headers:
            result["headers"] = important_headers
        
        self.requests.append(result)
    
    def handle_request(self, request: Request) -> None:
        """Fallback: Erfasst Requests über Playwright API (für Kompatibilität)."""
        # Wird nicht mehr primär genutzt, CDP handle_cdp_request ist die Hauptquelle
        pass
    
    def handle_response(self, response: Response) -> None:
        """Erfasst Response-Daten (Header)."""
        url = response.url
        
        try:
            headers = response.headers
            
            # Extrahiere wichtige Response-Header
            important = {}
            
            # Set-Cookie Header (DSGVO-relevant!)
            for key, value in headers.items():
                lower_key = key.lower()
                if lower_key in [
                    "set-cookie",
                    "content-security-policy",
                    "referrer-policy",
                    "permissions-policy",
                    "x-frame-options",
                    "access-control-allow-origin",
                ]:
                    important[key] = value
            
            if important:
                self.responses[url] = {
                    "status": response.status,
                    "headers": important,
                }
        except Exception:
            pass
    
    def handle_websocket(self, url: str) -> None:
        """Erfasst WebSocket-Verbindungen."""
        extracted = tldextract.extract(url)
        base_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        
        self.websockets.append({
            "url": url,
            "base_domain": base_domain,
            "is_third_party": base_domain != self.site_domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    
    def get_snapshot(self) -> dict:
        """Gibt einen Snapshot der gesammelten Daten zurück."""
        return {
            "requests": list(self.requests),
            "websockets": list(self.websockets),
            "response_headers": dict(self.responses),
        }
    
    def clear(self) -> None:
        """Löscht alle gesammelten Daten für neue Phase."""
        self.requests.clear()
        self.responses.clear()
        self.websockets.clear()
        self._seen_urls.clear()


# =============================================================================
# CONSENT BANNER HANDLING
# =============================================================================

class ConsentHandler:
    """Findet und interagiert mit Cookie-Consent-Bannern."""
    
    def __init__(self, page: Page):
        self.page = page
        self.detected_cmp: str | None = None
        self.banner_found = False
        self.click_success = False
        self.error_message: str | None = None
    
    def _try_click_in_frame(self, frame, cmp_name: str, selectors: list) -> bool:
        """Versucht in einem Frame/Page den Accept-Button zu klicken."""
        for selector in selectors:
            try:
                button = frame.locator(selector).first
                if button.is_visible(timeout=500):
                    button.click(timeout=2000)
                    self.detected_cmp = cmp_name
                    self.banner_found = True
                    self.click_success = True
                    return True
            except Exception:
                continue
        return False
    
    def _try_text_search_in_frame(self, frame) -> bool:
        """Versucht per Text-Suche den Accept-Button in einem Frame zu finden."""
        for text in get_all_accept_texts():
            try:
                for tag in ["button", "a", "[role='button']", "span", "div"]:
                    selector = f"{tag}:has-text('{text}')"
                    try:
                        elements = frame.locator(selector)
                        count = elements.count()
                        
                        for i in range(min(count, 3)):
                            element = elements.nth(i)
                            if element.is_visible(timeout=300):
                                element.click(timeout=2000)
                                self.detected_cmp = "text_fallback"
                                self.banner_found = True
                                self.click_success = True
                                return True
                    except Exception:
                        continue
            except Exception:
                continue
        return False
    
    def find_and_accept(self) -> bool:
        """
        Versucht das Consent-Banner zu finden und "Alle akzeptieren" zu klicken.
        Sucht sowohl im Hauptdokument als auch in iframes (wichtig für Sourcepoint etc.)
        
        Returns:
            True wenn erfolgreich geklickt, False sonst.
        """
        # Schritt 1: Versuche CMP-spezifische Selektoren im Hauptdokument
        for cmp_name, selectors in CMP_ACCEPT_SELECTORS.items():
            if self._try_click_in_frame(self.page, cmp_name, selectors):
                return True
        
        # Schritt 2: Suche in allen iframes (wichtig für Sourcepoint, etc.)
        try:
            frames = self.page.frames
            for frame in frames:
                if frame == self.page.main_frame:
                    continue  # Hauptframe bereits geprüft
                
                # Versuche CMP-Selektoren im iframe
                for cmp_name, selectors in CMP_ACCEPT_SELECTORS.items():
                    if self._try_click_in_frame(frame, f"{cmp_name}_iframe", selectors):
                        return True
                
                # Text-Suche im iframe
                if self._try_text_search_in_frame(frame):
                    return True
        except Exception:
            pass
        
        # Schritt 3: Text-basierte Suche im Hauptdokument
        if self._try_text_search_in_frame(self.page):
            return True
        
        # Schritt 4: Prüfe ob Banner sichtbar ist (auch wenn Klick fehlschlug)
        for selector in BANNER_CONTAINER_SELECTORS:
            try:
                if self.page.locator(selector).first.is_visible(timeout=300):
                    self.banner_found = True
                    self.error_message = "Banner gefunden, aber Accept-Button nicht klickbar"
                    return False
            except Exception:
                continue
        
        # Schritt 5: Prüfe iframes auf Banner-Container
        try:
            for frame in self.page.frames:
                if frame == self.page.main_frame:
                    continue
                for selector in BANNER_CONTAINER_SELECTORS:
                    try:
                        if frame.locator(selector).first.is_visible(timeout=200):
                            self.banner_found = True
                            self.error_message = "Banner in iframe gefunden, aber Accept-Button nicht klickbar"
                            return False
                    except Exception:
                        continue
        except Exception:
            pass
        
        self.error_message = "Kein Consent-Banner gefunden"
        return False
    
    def get_status(self) -> dict:
        """Gibt Status-Informationen zurück."""
        return {
            "banner_found": self.banner_found,
            "click_success": self.click_success,
            "detected_cmp": self.detected_cmp,
            "error": self.error_message,
        }


# =============================================================================
# PAGE STATE SNAPSHOT
# =============================================================================

def capture_cookies(context: BrowserContext) -> list[dict]:
    """Erfasst alle Cookies mit relevanten Attributen."""
    cookies = context.cookies()
    result = []
    
    for cookie in cookies:
        result.append({
            "name": cookie.get("name"),
            "domain": cookie.get("domain"),
            "path": cookie.get("path", "/"),
            "value_length": len(cookie.get("value", "")),  # Nicht den Wert selbst (Datenschutz)
            "value_preview": cookie.get("value", "")[:50] + "..." if len(cookie.get("value", "")) > 50 else cookie.get("value", ""),
            "httpOnly": cookie.get("httpOnly", False),
            "secure": cookie.get("secure", False),
            "sameSite": cookie.get("sameSite", "None"),
            "expires": cookie.get("expires", -1),
        })
    
    return result


def capture_storage(page: Page) -> dict:
    """Erfasst localStorage und sessionStorage."""
    storage = {"localStorage": {}, "sessionStorage": {}}
    
    try:
        # localStorage
        local_storage = page.evaluate("""() => {
            const items = {};
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                const value = localStorage.getItem(key);
                items[key] = value.length > 200 ? value.substring(0, 200) + '...' : value;
            }
            return items;
        }""")
        storage["localStorage"] = local_storage or {}
    except Exception:
        pass
    
    try:
        # sessionStorage
        session_storage = page.evaluate("""() => {
            const items = {};
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                const value = sessionStorage.getItem(key);
                items[key] = value.length > 200 ? value.substring(0, 200) + '...' : value;
            }
            return items;
        }""")
        storage["sessionStorage"] = session_storage or {}
    except Exception:
        pass
    
    return storage


def capture_page_policies(page: Page) -> dict:
    """Erfasst Sicherheits-/Privacy-Policies der Seite."""
    policies = {}
    
    try:
        # Meta-Tags
        policies["meta_tags"] = page.evaluate("""() => {
            const tags = {};
            const metaElements = document.querySelectorAll('meta');
            metaElements.forEach(meta => {
                const name = meta.getAttribute('name') || meta.getAttribute('http-equiv');
                if (name && ['referrer', 'robots', 'googlebot'].includes(name.toLowerCase())) {
                    tags[name] = meta.getAttribute('content');
                }
            });
            return tags;
        }""")
    except Exception:
        policies["meta_tags"] = {}
    
    try:
        # Permissions Policy API (wenn verfügbar)
        policies["permissions"] = page.evaluate("""() => {
            if (document.featurePolicy) {
                return document.featurePolicy.allowedFeatures();
            }
            return null;
        }""")
    except Exception:
        policies["permissions"] = None
    
    return policies


def capture_state_snapshot(
    page: Page,
    context: BrowserContext,
    collector: DataCollector,
) -> dict:
    """Erfasst einen vollständigen Zustandsschnappschuss."""
    network_data = collector.get_snapshot()
    
    return {
        "cookies": capture_cookies(context),
        "storage": capture_storage(page),
        "requests": network_data["requests"],
        "websockets": network_data["websockets"],
        "response_headers_sample": network_data["response_headers"],
    }


# =============================================================================
# DOMAIN KATEGORISIERUNG
# =============================================================================

def categorize_domain(domain: str) -> str | None:
    """Kategorisiert eine Domain basierend auf bekannten Tracking-Services."""
    for category, domains in KNOWN_TRACKING_CATEGORIES.items():
        for known_domain in domains:
            if domain == known_domain or domain.endswith("." + known_domain):
                return category
    return None


def add_domain_categories(requests: list[dict]) -> list[dict]:
    """Fügt Kategorisierung zu Requests hinzu."""
    for req in requests:
        category = categorize_domain(req.get("base_domain", ""))
        if category:
            req["category"] = category
    return requests


# =============================================================================
# HAUPTSCANNER
# =============================================================================

def scan_url(url: str) -> dict:
    """
    Führt einen vollständigen Privacy-Scan einer URL durch.
    
    Args:
        url: Die zu scannende URL (mit https://)
    
    Returns:
        Dict mit allen erfassten Daten.
    """
    # URL normalisieren
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    parsed = urlparse(url)
    extracted = tldextract.extract(url)
    site_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    
    result = {
        "scan_meta": {
            "url": url,
            "domain": site_domain,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner_version": "1.0.0",
            "consent_interaction": {},
        },
        "pre_consent": {},
        "post_consent": {},
        "page_policies": {},
        "errors": [],
    }
    
    with sync_playwright() as p:
        # Browser starten
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
            ]
        )
        
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            locale="de-DE",
        )
        
        page = context.new_page()
        
        # Data Collector initialisieren
        collector = DataCollector(site_domain)
        
        # CDP Session für vollständiges Request-Tracking mit Initiator-Daten
        cdp: CDPSession = context.new_cdp_session(page)
        
        # Network Events aktivieren und abonnieren
        cdp.send("Network.enable")
        cdp.on("Network.requestWillBeSent", collector.handle_cdp_request)
        
        # Zusätzliche Event Listener für Response-Daten und WebSockets
        page.on("response", collector.handle_response)
        page.on("websocket", lambda ws: collector.handle_websocket(ws.url))
        
        try:
            # =========================================================
            # PHASE 1: Pre-Consent
            # =========================================================
            
            # Seite laden
            page.goto(
                url,
                wait_until="networkidle",
                timeout=ScanConfig.PAGE_LOAD_TIMEOUT,
            )
            
            # Warten für verzögerte Skripte und Consent-Banner
            page.wait_for_timeout(3000)
            
            # Snapshot 1: Pre-Consent Zustand
            result["pre_consent"] = capture_state_snapshot(page, context, collector)
            result["pre_consent"]["requests"] = add_domain_categories(
                result["pre_consent"]["requests"]
            )
            
            # Page Policies erfassen
            result["page_policies"] = capture_page_policies(page)
            
            # =========================================================
            # CONSENT INTERAKTION
            # =========================================================
            
            # Collector für Post-Consent leeren
            collector.clear()
            
            # Consent Banner suchen und akzeptieren
            consent_handler = ConsentHandler(page)
            consent_success = consent_handler.find_and_accept()
            result["scan_meta"]["consent_interaction"] = consent_handler.get_status()
            
            # =========================================================
            # PHASE 2: Post-Consent
            # =========================================================
            
            if consent_success:
                # Warten auf nachgeladene Skripte
                page.wait_for_timeout(ScanConfig.POST_CONSENT_WAIT)
                
                # Versuche auf Network Idle zu warten
                try:
                    page.wait_for_load_state("networkidle", timeout=ScanConfig.NETWORK_IDLE_TIMEOUT)
                except PlaywrightTimeout:
                    pass  # OK, manche Seiten werden nie "idle"
            else:
                # Auch ohne Consent warten (für Vergleich)
                page.wait_for_timeout(3000)
            
            # Snapshot 2: Post-Consent Zustand
            result["post_consent"] = capture_state_snapshot(page, context, collector)
            result["post_consent"]["requests"] = add_domain_categories(
                result["post_consent"]["requests"]
            )
            
        except PlaywrightTimeout as e:
            result["errors"].append({
                "type": "timeout",
                "message": str(e),
                "phase": "page_load",
            })
        except Exception as e:
            result["errors"].append({
                "type": "general",
                "message": str(e),
                "phase": "scan",
            })
        finally:
            browser.close()
    
    # Zusammenfassung erstellen
    result["summary"] = create_summary(result)
    
    return result


def create_summary(data: dict) -> dict:
    """Erstellt eine Zusammenfassung der erfassten Daten."""
    pre = data.get("pre_consent", {})
    post = data.get("post_consent", {})
    
    def count_third_party(requests: list) -> int:
        return sum(1 for r in requests if r.get("is_third_party"))
    
    def unique_domains(requests: list) -> list:
        return list(set(r.get("base_domain") for r in requests if r.get("is_third_party")))
    
    def count_by_category(requests: list) -> dict:
        categories = {}
        for r in requests:
            cat = r.get("category")
            if cat:
                categories[cat] = categories.get(cat, 0) + 1
        return categories
    
    def analyze_initiator_chains(requests: list) -> dict:
        """Analysiert welche Scripts andere Third-Party-Requests auslösen."""
        chains = {}  # initiator_domain -> [triggered_domains]
        
        for req in requests:
            if not req.get("is_third_party"):
                continue
            
            initiator = req.get("initiator", {})
            triggered_by = initiator.get("triggered_by_domain") or initiator.get("base_domain")
            
            if triggered_by:
                target_domain = req.get("base_domain")
                if triggered_by not in chains:
                    chains[triggered_by] = set()
                chains[triggered_by].add(target_domain)
        
        # Konvertiere Sets zu sortierten Listen
        return {k: sorted(list(v)) for k, v in chains.items()}
    
    def find_direct_html_includes(requests: list) -> list:
        """Findet Third-Party Scripts die direkt im HTML eingebunden sind."""
        direct = []
        for req in requests:
            if not req.get("is_third_party"):
                continue
            if req.get("resource_type") != "script":
                continue
            
            initiator = req.get("initiator", {})
            # "parser" = direkt im HTML, nicht durch JS geladen
            if initiator.get("type") == "parser":
                direct.append({
                    "domain": req.get("base_domain"),
                    "url": req.get("url"),
                })
        return direct
    
    return {
        "pre_consent": {
            "total_cookies": len(pre.get("cookies", [])),
            "total_requests": len(pre.get("requests", [])),
            "third_party_requests": count_third_party(pre.get("requests", [])),
            "third_party_domains": unique_domains(pre.get("requests", [])),
            "requests_by_category": count_by_category(pre.get("requests", [])),
            "localStorage_keys": len(pre.get("storage", {}).get("localStorage", {})),
            "sessionStorage_keys": len(pre.get("storage", {}).get("sessionStorage", {})),
            "initiator_chains": analyze_initiator_chains(pre.get("requests", [])),
            "direct_html_scripts": find_direct_html_includes(pre.get("requests", [])),
        },
        "post_consent": {
            "total_cookies": len(post.get("cookies", [])),
            "total_requests": len(post.get("requests", [])),
            "third_party_requests": count_third_party(post.get("requests", [])),
            "third_party_domains": unique_domains(post.get("requests", [])),
            "requests_by_category": count_by_category(post.get("requests", [])),
            "localStorage_keys": len(post.get("storage", {}).get("localStorage", {})),
            "sessionStorage_keys": len(post.get("storage", {}).get("sessionStorage", {})),
            "initiator_chains": analyze_initiator_chains(post.get("requests", [])),
            "direct_html_scripts": find_direct_html_includes(post.get("requests", [])),
        },
        "changes": {
            "new_cookies": len(post.get("cookies", [])) - len(pre.get("cookies", [])),
            "new_requests": len(post.get("requests", [])),
        }
    }


def generate_filename(url: str, compact: bool = True) -> str:
    """Generiert einen Dateinamen aus der URL."""
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")
    # Ersetze ungültige Zeichen
    safe_name = re.sub(r"[^a-zA-Z0-9.-]", "_", domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = "_detailed" if not compact else ""
    return f"{safe_name}_{timestamp}{suffix}.json"


def compact_results(data: dict) -> dict:
    """
    Komprimiert die Scan-Ergebnisse für kleinere Dateigröße.
    Aggregiert Requests nach Domain, entfernt redundante Daten.
    """
    def compact_requests(requests: list) -> list:
        """Aggregiert Requests nach Domain."""
        domain_stats: dict[str, dict] = {}
        
        for req in requests:
            domain = req.get("base_domain", "unknown")
            
            if domain not in domain_stats:
                domain_stats[domain] = {
                    "domain": domain,
                    "is_third_party": req.get("is_third_party", False),
                    "request_count": 0,
                    "resource_types": set(),
                    "initiators": set(),
                    "example_paths": [],
                }
            
            stats = domain_stats[domain]
            stats["request_count"] += 1
            stats["resource_types"].add(req.get("resource_type", "unknown"))
            
            # Initiator-Domain extrahieren
            initiator = req.get("initiator", {})
            triggered_by = initiator.get("triggered_by_domain") or initiator.get("base_domain")
            if triggered_by:
                stats["initiators"].add(triggered_by)
            
            # Ein paar Beispiel-Pfade speichern (ohne Query-String)
            if len(stats["example_paths"]) < 3:
                url = req.get("url", "")
                parsed = urlparse(url)
                path = parsed.path[:50] if parsed.path else "/"
                if path not in stats["example_paths"]:
                    stats["example_paths"].append(path)
        
        # Sets zu Listen konvertieren und sortieren
        result = []
        for domain, stats in sorted(domain_stats.items(), key=lambda x: -x[1]["request_count"]):
            result.append({
                "domain": stats["domain"],
                "is_third_party": stats["is_third_party"],
                "request_count": stats["request_count"],
                "resource_types": sorted(stats["resource_types"]),
                "triggered_by": sorted(stats["initiators"]) if stats["initiators"] else None,
                "example_paths": stats["example_paths"],
            })
        
        return result
    
    def compact_cookies(cookies: list) -> list:
        """Reduziert Cookie-Daten auf das Wesentliche."""
        return [
            {
                "name": c.get("name"),
                "domain": c.get("domain"),
                "httpOnly": c.get("httpOnly"),
                "secure": c.get("secure"),
                "sameSite": c.get("sameSite"),
            }
            for c in cookies
        ]
    
    def compact_storage(storage: dict) -> dict:
        """Reduziert Storage auf Keys."""
        return {
            "localStorage_keys": list(storage.get("localStorage", {}).keys()),
            "sessionStorage_keys": list(storage.get("sessionStorage", {}).keys()),
        }
    
    # Komprimierte Version erstellen
    compact = {
        "scan_meta": data.get("scan_meta", {}),
        "pre_consent": {
            "cookies": compact_cookies(data.get("pre_consent", {}).get("cookies", [])),
            "storage": compact_storage(data.get("pre_consent", {}).get("storage", {})),
            "requests": compact_requests(data.get("pre_consent", {}).get("requests", [])),
        },
        "post_consent": {
            "cookies": compact_cookies(data.get("post_consent", {}).get("cookies", [])),
            "storage": compact_storage(data.get("post_consent", {}).get("storage", {})),
            "requests": compact_requests(data.get("post_consent", {}).get("requests", [])),
        },
        "summary": data.get("summary", {}),
    }
    
    # Response Headers und page_policies weglassen
    
    return compact


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Hauptfunktion - CLI Entry Point."""
    if len(sys.argv) < 2:
        print("Verwendung: python privacy_scanner.py <URL> [--detailed]", file=sys.stderr)
        print("", file=sys.stderr)
        print("Beispiele:", file=sys.stderr)
        print("  python privacy_scanner.py https://example.com           # Kompakt (Standard)", file=sys.stderr)
        print("  python privacy_scanner.py https://example.com --detailed  # Volle Details", file=sys.stderr)
        sys.exit(1)
    
    url = sys.argv[1]
    detailed_mode = "--detailed" in sys.argv
    
    # Scan durchführen
    result = scan_url(url)
    
    # Standard: Kompakt. Mit --detailed: volle Daten
    if not detailed_mode:
        result = compact_results(result)
    
    # Ausgabe in Datei
    filename = generate_filename(url, compact=not detailed_mode)
    output_path = Path(filename)
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    # Kurze Bestätigung auf stderr (JSON bleibt sauber auf stdout)
    size_kb = output_path.stat().st_size / 1024
    mode_info = "detailliert" if detailed_mode else "kompakt"
    print(f"Scan abgeschlossen ({mode_info}). Ergebnis: {filename} ({size_kb:.1f} KB)", file=sys.stderr)
    
    # JSON auch auf stdout ausgeben (für Piping)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
