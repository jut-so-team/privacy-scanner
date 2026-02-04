"""
Consent Banner Selektoren - Übersicht aller unterstützten Anbieter

Diese Datei enthält alle CSS-Selektoren und Text-Patterns für die
automatische Erkennung und Interaktion mit Cookie-Consent-Bannern.

WARTUNGSHINWEIS: Selektoren können sich ändern, wenn Anbieter Updates
durchführen. Letzte Aktualisierung: Februar 2025
"""

# =============================================================================
# CONSENT MANAGEMENT PLATFORMS (CMPs) - CSS SELEKTOREN
# =============================================================================
# Jeder Eintrag enthält: (Selektor für "Alle akzeptieren" Button)
# Sortiert nach Marktanteil/Verbreitung

CMP_ACCEPT_SELECTORS = {
    # -------------------------------------------------------------------------
    # OneTrust (sehr verbreitet, z.B. bei großen Konzernen)
    # -------------------------------------------------------------------------
    "onetrust": [
        "#onetrust-accept-btn-handler",
        ".onetrust-accept-btn-handler",
        "#accept-recommended-btn-handler",
        "[data-testid='accept-all']",
    ],
    
    # -------------------------------------------------------------------------
    # Cookiebot (weit verbreitet in EU)
    # -------------------------------------------------------------------------
    "cookiebot": [
        "#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll",
        "#CybotCookiebotDialogBodyButtonAccept",
        "#CybotCookiebotDialogBodyLevelButtonAccept",
        "[data-cookiebanner='accept_button']",
    ],
    
    # -------------------------------------------------------------------------
    # Usercentrics (häufig in DACH-Region)
    # -------------------------------------------------------------------------
    "usercentrics": [
        "[data-testid='uc-accept-all-button']",
        "#uc-btn-accept-banner",
        ".uc-btn-accept-banner",
        "button[data-testid='uc-accept-all-button']",
    ],
    
    # -------------------------------------------------------------------------
    # Didomi (international verbreitet)
    # -------------------------------------------------------------------------
    "didomi": [
        "#didomi-notice-agree-button",
        "[data-testid='didomi-agree-button']",
        ".didomi-continue-without-agreeing",
        "#didomi-popup .didomi-button-highlight",
    ],
    
    # -------------------------------------------------------------------------
    # TrustArc / TRUSTe
    # -------------------------------------------------------------------------
    "trustarc": [
        ".trustarc-agree-btn",
        "#truste-consent-button",
        ".pdynamicbutton .call",
        "#consent_prompt_submit",
    ],
    
    # -------------------------------------------------------------------------
    # Quantcast Choice
    # -------------------------------------------------------------------------
    "quantcast": [
        ".qc-cmp2-summary-buttons button[mode='primary']",
        ".qc-cmp-button[data-tracking='accept-all']",
        ".qc-cmp2-button--agree",
        "#qcCmpButtons button:first-child",
    ],
    
    # -------------------------------------------------------------------------
    # Borlabs Cookie (WordPress Plugin, sehr verbreitet)
    # -------------------------------------------------------------------------
    "borlabs": [
        "#CookieBoxSaveButton",
        ".BorlabsCookie ._brlbs-btn-accept-all",
        "a[data-cookie-accept-all]",
        "#BorlabsCookieBox a[data-cookie-accept-all='true']",
    ],
    
    # -------------------------------------------------------------------------
    # Complianz (WordPress Plugin)
    # -------------------------------------------------------------------------
    "complianz": [
        ".cmplz-accept",
        ".cmplz-btn.cmplz-accept",
        "#cmplz-cookiebanner-container .cmplz-accept",
        "button.cmplz-accept-all",
    ],
    
    # -------------------------------------------------------------------------
    # GDPR Cookie Compliance (WordPress)
    # -------------------------------------------------------------------------
    "gdpr_cookie_compliance": [
        "#moove_gdpr_cookie_modal .moove-gdpr-modal-allow-all",
        ".gdpr_lightbox .gdpr-allow-all",
        "#moove_gdpr_cookie_info_bar .mgbutton",
    ],
    
    # -------------------------------------------------------------------------
    # Cookie Notice (WordPress)
    # -------------------------------------------------------------------------
    "cookie_notice": [
        "#cn-accept-cookie",
        ".cn-accept-cookie",
        "#cookie-notice .cn-button",
    ],
    
    # -------------------------------------------------------------------------
    # CookieYes / Cookie Law Info
    # -------------------------------------------------------------------------
    "cookieyes": [
        "#cookie_action_close_header",
        ".cky-btn-accept",
        "[data-cky-tag='accept-button']",
        "#cky-btn-accept",
    ],
    
    # -------------------------------------------------------------------------
    # Osano
    # -------------------------------------------------------------------------
    "osano": [
        ".osano-cm-accept-all",
        ".osano-cm-dialog__buttons .osano-cm-button--type_accept",
        "button[data-type='accept']",
    ],
    
    # -------------------------------------------------------------------------
    # Termly
    # -------------------------------------------------------------------------
    "termly": [
        "[data-tid='banner-accept']",
        ".t-acceptAllButton",
        "#termly-code-snippet-support .t-accept-all-btn",
    ],
    
    # -------------------------------------------------------------------------
    # iubenda
    # -------------------------------------------------------------------------
    "iubenda": [
        ".iubenda-cs-accept-btn",
        "#iubenda-cs-banner .iubenda-cs-accept-btn",
        ".iub-cmp-button[data-iub-action='accept']",
    ],
    
    # -------------------------------------------------------------------------
    # Klaro
    # -------------------------------------------------------------------------
    "klaro": [
        ".klaro .cm-btn-accept-all",
        ".klaro .cm-btn-success",
        ".klaro button[data-name='accept']",
    ],
    
    # -------------------------------------------------------------------------
    # Admiral (Cookie Consent)
    # -------------------------------------------------------------------------
    "admiral": [
        ".admiral-cmp-accept",
        "[data-admiral-action='accept-all']",
    ],
    
    # -------------------------------------------------------------------------
    # Sourcepoint (häufig in iframe!)
    # -------------------------------------------------------------------------
    "sourcepoint": [
        "button[title='Accept All']",
        "button[title='Alle akzeptieren']",
        "button[title='Zustimmen']",
        "button[title='ZUSTIMMEN']",
        ".sp_choice_type_11",  # Accept all button type
        ".sp_choice_type_ACCEPT_ALL",
        "[data-sp-action='accept']",
        "button.message-component.message-button",  # Generic Sourcepoint button
    ],
    
    # -------------------------------------------------------------------------
    # LiveRamp / Faktor.io
    # -------------------------------------------------------------------------
    "liveramp": [
        ".fides-accept-all-button",
        "#fides-button-group .fides-accept-button",
    ],
    
    # -------------------------------------------------------------------------
    # Consentmanager.net
    # -------------------------------------------------------------------------
    "consentmanager": [
        "#cmpbntyestxt",
        ".cmpboxbtns .cmpboxbtnyes",
        "#cmpbox .cmpboxbtn.cmpboxbtnyes",
    ],
    
    # -------------------------------------------------------------------------
    # Cookie Script
    # -------------------------------------------------------------------------
    "cookiescript": [
        "#cookiescript_accept",
        ".cookiescript_accept",
        "#cookiescript_wrapper #cookiescript_accept",
    ],
    
    # -------------------------------------------------------------------------
    # Civic Cookie Control
    # -------------------------------------------------------------------------
    "civic": [
        "#ccc-recommended-settings",
        ".ccc-accept-button",
        "#ccc button.ccc-accept",
    ],
    
    # -------------------------------------------------------------------------
    # TYPO3 Cookie Consent
    # -------------------------------------------------------------------------
    "typo3": [
        ".cc-compliance .cc-btn.cc-allow",
        ".cc-banner .cc-btn.cc-accept-all",
    ],
    
    # -------------------------------------------------------------------------
    # Shopify Cookie Banner
    # -------------------------------------------------------------------------
    "shopify": [
        ".shopify-cookie-banner__accept",
        "[data-shopify-cookie-consent-accept]",
    ],
}

# =============================================================================
# TEXT-BASIERTE ERKENNUNG (Fallback)
# =============================================================================
# Mehrsprachige Texte für "Alle akzeptieren" Buttons
# Verwendet für: button:has-text(), Aria-Labels, etc.

ACCEPT_BUTTON_TEXTS = {
    # Deutsch
    "de": [
        "Alle akzeptieren",
        "Alle Cookies akzeptieren",
        "Alles akzeptieren",
        "Akzeptieren",
        "Alle zulassen",
        "Zustimmen",
        "Ich stimme zu",
        "Einverstanden",
        "OK",
        "Verstanden",
        "Annehmen",
    ],
    
    # Englisch
    "en": [
        "Accept all",
        "Accept all cookies",
        "Accept cookies",
        "Accept",
        "Allow all",
        "Allow all cookies",
        "I agree",
        "I accept",
        "Agree",
        "Got it",
        "OK",
        "Consent",
        "Yes, I agree",
        "Continue",
    ],
    
    # Französisch
    "fr": [
        "Tout accepter",
        "Accepter tout",
        "Accepter tous les cookies",
        "Accepter",
        "J'accepte",
        "Autoriser tout",
        "D'accord",
        "Continuer",
    ],
    
    # Spanisch
    "es": [
        "Aceptar todo",
        "Aceptar todas",
        "Aceptar cookies",
        "Aceptar",
        "Acepto",
        "Permitir todo",
        "De acuerdo",
    ],
    
    # Italienisch
    "it": [
        "Accetta tutto",
        "Accetta tutti",
        "Accetta tutti i cookie",
        "Accetta",
        "Accetto",
        "Consenti tutto",
        "OK",
    ],
    
    # Niederländisch
    "nl": [
        "Alles accepteren",
        "Alle cookies accepteren",
        "Accepteren",
        "Akkoord",
        "Ik ga akkoord",
    ],
    
    # Polnisch
    "pl": [
        "Zaakceptuj wszystkie",
        "Akceptuję wszystkie",
        "Akceptuję",
        "Zgadzam się",
    ],
    
    # Portugiesisch
    "pt": [
        "Aceitar tudo",
        "Aceitar todos",
        "Aceitar cookies",
        "Aceitar",
        "Concordo",
    ],
}

# =============================================================================
# BANNER CONTAINER SELEKTOREN
# =============================================================================
# Selektoren um das Consent-Banner selbst zu finden (für Sichtbarkeitsprüfung)

BANNER_CONTAINER_SELECTORS = [
    # Generische IDs
    "#cookie-banner",
    "#cookie-consent",
    "#cookie-notice",
    "#cookie-popup",
    "#cookie-bar",
    "#gdpr-banner",
    "#gdpr-consent",
    "#consent-banner",
    "#consent-popup",
    "#privacy-banner",
    
    # CMP-spezifisch
    "#onetrust-banner-sdk",
    "#CybotCookiebotDialog",
    "#usercentrics-root",
    "#didomi-popup",
    "#truste-consent-track",
    ".qc-cmp2-container",
    "#BorlabsCookieBox",
    "#moove_gdpr_cookie_modal",
    ".iubenda-cs-container",
    ".klaro",
    "#cmpbox",
    "#cookiescript_injected",
    
    # Generische Klassen
    ".cookie-banner",
    ".cookie-consent",
    ".cookie-notice",
    ".gdpr-banner",
    ".consent-banner",
    ".privacy-notice",
    
    # Aria/Role basiert
    "[role='dialog'][aria-label*='cookie' i]",
    "[role='dialog'][aria-label*='consent' i]",
    "[role='alertdialog'][aria-label*='cookie' i]",
]

# =============================================================================
# ABLEHNEN-BUTTON SELEKTOREN (für zukünftige Erweiterung)
# =============================================================================
# Kann verwendet werden um "Nur notwendige" oder "Ablehnen" zu klicken

REJECT_BUTTON_TEXTS = {
    "de": [
        "Ablehnen",
        "Nur notwendige",
        "Nur essenzielle",
        "Nur erforderliche",
        "Nicht zustimmen",
    ],
    "en": [
        "Reject all",
        "Decline",
        "Only necessary",
        "Only essential",
        "Deny",
    ],
}


def get_all_accept_selectors() -> list[str]:
    """
    Gibt alle CSS-Selektoren für Accept-Buttons zurück.
    Flacht die CMP-spezifischen Selektoren in eine Liste.
    """
    selectors = []
    for cmp_selectors in CMP_ACCEPT_SELECTORS.values():
        selectors.extend(cmp_selectors)
    return selectors


def get_all_accept_texts() -> list[str]:
    """
    Gibt alle Accept-Button Texte (alle Sprachen) zurück.
    """
    texts = []
    for lang_texts in ACCEPT_BUTTON_TEXTS.values():
        texts.extend(lang_texts)
    return list(set(texts))  # Duplikate entfernen


def get_text_based_selectors() -> list[str]:
    """
    Generiert Playwright-kompatible Text-Selektoren.
    Verwendet :has-text() für fuzzy matching.
    """
    texts = get_all_accept_texts()
    selectors = []
    
    for text in texts:
        # Button mit exaktem oder enthaltenem Text
        selectors.append(f"button:has-text('{text}')")
        selectors.append(f"a:has-text('{text}')")
        selectors.append(f"[role='button']:has-text('{text}')")
        
    return selectors
