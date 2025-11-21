#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
German translation script for django.po file
Translates only application-specific strings, leaving Django framework strings empty
"""

import re
import codecs

# German translations for application-specific strings
TRANSLATIONS = [
    # Forms
    ('msgid "Select Domain"\\nmsgstr ""', 'msgid "Select Domain"\\nmsgstr "Domain auswählen"'),
    ('msgid "e.g. app1"\\nmsgstr ""', 'msgid "e.g. app1"\\nmsgstr "z.B. app1"'),
    ('msgid "Certificate File"\\nmsgstr ""', 'msgid "Certificate File"\\nmsgstr "Zertifikatsdatei"'),
    ('msgid "Upload certificate (.crt, .cer, .pem)"\\nmsgstr ""', 'msgid "Upload certificate (.crt, .cer, .pem)"\\nmsgstr "Zertifikat hochladen (.crt, .cer, .pem)"'),
    
    # Models
    ('msgid "Administrator"\\nmsgstr ""', 'msgid "Administrator"\\nmsgstr "Administrator"'),
    ('msgid "Normal User"\\nmsgstr ""', 'msgid "Normal User"\\nmsgstr "Normaler Benutzer"'),
    ('msgid "Number of previous passwords to remember"\\nmsgstr ""', 'msgid "Number of previous passwords to remember"\\nmsgstr "Anzahl der zu merkenden vorherigen Passwörter"'),
    ('msgid "Pending"\\nmsgstr ""', 'msgid "Pending"\\nmsgstr "Ausstehend"'),
    ('msgid "Issued"\\nmsgstr ""', 'msgid "Issued"\\nmsgstr "Ausgestellt"'),
    ('msgid "Signed"\\nmsgstr ""', 'msgid "Signed"\\nmsgstr "Signiert"'),
    ('msgid "Revoked"\\nmsgstr ""', 'msgid "Revoked"\\nmsgstr "Widerrufen"'),
    ('msgid "Session key for anonymous users"\\nmsgstr ""', 'msgid "Session key for anonymous users"\\nmsgstr "Sitzungsschlüssel für anonyme Benutzer"'),
    ('msgid "User if authenticated"\\nmsgstr ""', 'msgid "User if authenticated"\\nmsgstr "Benutzer wenn authentifiziert"'),
    
    # Base template
    ('msgid "SSL Manager"\\nmsgstr ""', 'msgid "SSL Manager"\\nmsgstr "SSL-Manager"'),
    ('msgid "Logout"\\nmsgstr ""', 'msgid "Logout"\\nmsgstr "Abmelden"'),
    ('msgid "Administration"\\nmsgstr ""', 'msgid "Administration"\\nmsgstr "Verwaltung"'),
    ('msgid "Login"\\nmsgstr ""', 'msgid "Login"\\nmsgstr "Anmelden"'),
    ('msgid "Learn more"\\nmsgstr ""', 'msgid "Learn more"\\nmsgstr "Mehr erfahren"'),
    
    # Certificate detail
    ('msgid "Details"\\nmsgstr ""', 'msgid "Details"\\nmsgstr "Details"'),
    ('msgid "Domain:"\\nmsgstr ""', 'msgid "Domain:"\\nmsgstr "Domain:"'),
    ('msgid "Created By:"\\nmsgstr ""', 'msgid "Created By:"\\nmsgstr "Erstellt von:"'),
    ('msgid "Created At:"\\nmsgstr ""', 'msgid "Created At:"\\nmsgstr "Erstellt am:"'),
    ('msgid "Organization:"\\nmsgstr ""', 'msgid "Organization:"\\nmsgstr "Organisation:"'),
    ('msgid "Unit:"\\nmsgstr ""', 'msgid "Unit:"\\nmsgstr "Abteilung:"'),
    ('msgid "Location:"\\nmsgstr ""', 'msgid "Location:"\\nmsgstr "Standort:"'),
    ('msgid "Download .csr"\\nmsgstr ""', 'msgid "Download .csr"\\nmsgstr ".csr herunterladen"'),
    ('msgid "Private Key"\\nmsgstr ""', 'msgid "Private Key"\\nmsgstr "Privater Schlüssel"'),
    ('msgid "Download .key"\\nmsgstr ""', 'msgid "Download .key"\\nmsgstr ".key herunterladen"'),
    ('msgid "Iteration History for"\\nmsgstr ""', 'msgid "Iteration History for"\\nmsgstr "Iterationsverlauf für"'),
    ('msgid "Generated"\\nmsgstr ""', 'msgid "Generated"\\nmsgstr "Generiert"'),
    ('msgid "Status"\\nmsgstr ""', 'msgid "Status"\\nmsgstr "Status"'),
    ('msgid "Valid From"\\nmsgstr ""', 'msgid "Valid From"\\nmsgstr "Gültig ab"'),
    ('msgid "Valid Until"\\nmsgstr ""', 'msgid "Valid Until"\\nmsgstr "Gültig bis"'),
    ('msgid "Created By"\\nmsgstr ""', 'msgid "Created By"\\nmsgstr "Erstellt von"'),
    ('msgid "Files"\\nmsgstr ""', 'msgid "Files"\\nmsgstr "Dateien"'),
    ('msgid "Upload Certificate"\\nmsgstr ""', 'msgid "Upload Certificate"\\nmsgstr "Zertifikat hochladen"'),
    ('msgid "Current"\\nmsgstr ""', 'msgid "Current"\\nmsgstr "Aktuell"'),
    ('msgid "View"\\nmsgstr ""', 'msgid "View"\\nmsgstr "Ansehen"'),
    ('msgid "Common Name:"\\nmsgstr ""', 'msgid "Common Name:"\\nmsgstr "Common Name:"'),
    ('msgid "Created:"\\nmsgstr ""', 'msgid "Created:"\\nmsgstr "Erstellt:"'),
    ('msgid "Accepted formats: .crt, .cer, .pem"\\nmsgstr ""', 'msgid "Accepted formats: .crt, .cer, .pem"\\nmsgstr "Akzeptierte Formate: .crt, .cer, .pem"'),
    ('msgid "Download PFX"\\nmsgstr ""', 'msgid "Download PFX"\\nmsgstr "PFX herunterladen"'),
    ('msgid "Back to Search"\\nmsgstr ""', 'msgid "Back to Search"\\nmsgstr "Zurück zur Suche"'),
    
    # CSR result
    ('msgid "Success!"\\nmsgstr ""', 'msgid "Success!"\\nmsgstr "Erfolg!"'),
    ('msgid "CSR and Private Key for"\\nmsgstr ""', 'msgid "CSR and Private Key for"\\nmsgstr "CSR und privater Schlüssel für"'),
    ('msgid "Certificate Signing Request (CSR)"\\nmsgstr ""', 'msgid "Certificate Signing Request (CSR)"\\nmsgstr "Zertifikatsignierungsanforderung (CSR)"'),
    ('msgid "Private Key (Keep Secret!)"\\nmsgstr ""', 'msgid "Private Key (Keep Secret!)"\\nmsgstr "Privater Schlüssel (Geheim halten!)"'),
    ('msgid "Return Home"\\nmsgstr ""', 'msgid "Return Home"\\nmsgstr "Zur Startseite"'),
    ('msgid "Generate Another"\\nmsgstr ""', 'msgid "Generate Another"\\nmsgstr "Weitere generieren"'),
    
    # Generate CSR
    ('msgid "Generate New CSR"\\nmsgstr ""', 'msgid "Generate New CSR"\\nmsgstr "Neuen CSR generieren"'),
    ('msgid "Domain Information"\\nmsgstr ""', 'msgid "Domain Information"\\nmsgstr "Domain-Informationen"'),
    ('msgid "Domain"\\nmsgstr ""', 'msgid "Domain"\\nmsgstr "Domain"'),
    ('msgid "Subdomain (App Name)"\\nmsgstr ""', 'msgid "Subdomain (App Name)"\\nmsgstr "Subdomain (App-Name)"'),
    ('msgid "e.g., \'app1\' for app1.example.com"\\nmsgstr ""', 'msgid "e.g., \'app1\' for app1.example.com"\\nmsgstr "z.B. \'app1\' für app1.example.com"'),
    ('msgid "Generate CSR & Key"\\nmsgstr ""', 'msgid "Generate CSR & Key"\\nmsgstr "CSR & Schlüssel generieren"'),
    ('msgid "Cancel"\\nmsgstr ""', 'msgid "Cancel"\\nmsgstr "Abbrechen"'),
    
    # Home
    ('msgid "Generate New"\\nmsgstr ""', 'msgid "Generate New"\\nmsgstr "Neu generieren"'),
    ('msgid "Create a new CSR and Private Key for your domain."\\nmsgstr ""', 'msgid "Create a new CSR and Private Key for your domain."\\nmsgstr "Erstellen Sie einen neuen CSR und privaten Schlüssel für Ihre Domain."'),
    ('msgid "Search Repository"\\nmsgstr ""', 'msgid "Search Repository"\\nmsgstr "Repository durchsuchen"'),
    ('msgid "Find existing certificates, keys, and CSRs."\\nmsgstr ""', 'msgid "Find existing certificates, keys, and CSRs."\\nmsgstr "Finden Sie vorhandene Zertifikate, Schlüssel und CSRs."'),
    
    # Login
    ('msgid "Username"\\nmsgstr ""', 'msgid "Username"\\nmsgstr "Benutzername"'),
    ('msgid "Password"\\nmsgstr ""', 'msgid "Password"\\nmsgstr "Passwort"'),
    ('msgid "Sign In"\\nmsgstr ""', 'msgid "Sign In"\\nmsgstr "Anmelden"'),
    
    # MFA
    ('msgid "Setup Two-Factor Authentication"\\nmsgstr ""', 'msgid "Setup Two-Factor Authentication"\\nmsgstr "Zwei-Faktor-Authentifizierung einrichten"'),
    ('msgid "Manual Entry Key:"\\nmsgstr ""', 'msgid "Manual Entry Key:"\\nmsgstr "Manueller Eingabeschlüssel:"'),
    ('msgid "Verify and Enable MFA"\\nmsgstr ""', 'msgid "Verify and Enable MFA"\\nmsgstr "MFA überprüfen und aktivieren"'),
    ('msgid "Two-Factor Authentication"\\nmsgstr ""', 'msgid "Two-Factor Authentication"\\nmsgstr "Zwei-Faktor-Authentifizierung"'),
    ('msgid "Enter the 6-digit code from your authenticator app"\\nmsgstr ""', 'msgid "Enter the 6-digit code from your authenticator app"\\nmsgstr "Geben Sie den 6-stelligen Code aus Ihrer Authenticator-App ein"'),
    ('msgid "Authentication Code:"\\nmsgstr ""', 'msgid "Authentication Code:"\\nmsgstr "Authentifizierungscode:"'),
    ('msgid "Trust this device for 7 days"\\nmsgstr ""', 'msgid "Trust this device for 7 days"\\nmsgstr "Diesem Gerät für 7 Tage vertrauen"'),
    ('msgid "Cookies not accepted:"\\nmsgstr ""', 'msgid "Cookies not accepted:"\\nmsgstr "Cookies nicht akzeptiert:"'),
    ('msgid "Verify"\\nmsgstr ""', 'msgid "Verify"\\nmsgstr "Überprüfen"'),
    ('msgid "Cancel and logout"\\nmsgstr ""', 'msgid "Cancel and logout"\\nmsgstr "Abbrechen und abmelden"'),
    
    # Password change
    ('msgid "Change Password"\\nmsgstr ""', 'msgid "Change Password"\\nmsgstr "Passwort ändern"'),
    ('msgid "Password Requirements:"\\nmsgstr ""', 'msgid "Password Requirements:"\\nmsgstr "Passwortanforderungen:"'),
    ('msgid "Minimum 12 characters (16 for Admins)"\\nmsgstr ""', 'msgid "Minimum 12 characters (16 for Admins)"\\nmsgstr "Mindestens 12 Zeichen (16 für Administratoren)"'),
    ('msgid "Must contain uppercase, lowercase, numbers, and special characters"\\nmsgstr ""', 'msgid "Must contain uppercase, lowercase, numbers, and special characters"\\nmsgstr "Muss Groß-, Kleinbuchstaben, Zahlen und Sonderzeichen enthalten"'),
    ('msgid "Cannot reuse any of your last 20 passwords"\\nmsgstr ""', 'msgid "Cannot reuse any of your last 20 passwords"\\nmsgstr "Kann keines Ihrer letzten 20 Passwörter wiederverwenden"'),
    ('msgid "Expires every 90 days"\\nmsgstr ""', 'msgid "Expires every 90 days"\\nmsgstr "Läuft alle 90 Tage ab"'),
    
    # Search
    ('msgid "Search by Common Name (live search)"\\nmsgstr ""', 'msgid "Search by Common Name (live search)"\\nmsgstr "Suche nach Common Name (Live-Suche)"'),
    ('msgid "Hold Ctrl for multiple domains"\\nmsgstr ""', 'msgid "Hold Ctrl for multiple domains"\\nmsgstr "Halten Sie Strg für mehrere Domains gedrückt"'),
    ('msgid "All"\\nmsgstr ""', 'msgid "All"\\nmsgstr "Alle"'),
    ('msgid "Expiring in 1 Month"\\nmsgstr ""', 'msgid "Expiring in 1 Month"\\nmsgstr "Läuft in 1 Monat ab"'),
    ('msgid "Show"\\nmsgstr ""', 'msgid "Show"\\nmsgstr "Anzeigen"'),
    ('msgid "entries"\\nmsgstr ""', 'msgid "entries"\\nmsgstr "Einträge"'),
    ('msgid "Common Name"\\nmsgstr ""', 'msgid "Common Name"\\nmsgstr "Common Name"'),
    ('msgid "Created"\\nmsgstr ""', 'msgid "Created"\\nmsgstr "Erstellt"'),
    ('msgid "Expires"\\nmsgstr ""', 'msgid "Expires"\\nmsgstr "Läuft ab"'),
    ('msgid "Actions"\\nmsgstr ""', 'msgid "Actions"\\nmsgstr "Aktionen"'),
    ('msgid "No certificates found."\\nmsgstr ""', 'msgid "No certificates found."\\nmsgstr "Keine Zertifikate gefunden."'),
]

def translate_po_file(input_path, output_path):
    """Translate the .po file with German translations"""
    print(f"Reading {input_path}...")
    
    with codecs.open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Remove fuzzy flag and set language
    content = content.replace('#, fuzzy\\n', '')
    content = content.replace('"Language: \\\\n"', '"Language: de\\\\n"')
    
    # Apply all translations
    for pattern, replacement in TRANSLATIONS:
        content = content.replace(pattern, replacement)
    
    # Write the translated content
    print(f"Writing to {output_path}...")
    with codecs.open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("Translation completed successfully!")
    print(f"Translated {len(TRANSLATIONS)} strings")

if __name__ == '__main__':
    input_file = r'c:\Users\andre\.gemini\antigravity\scratch\ssl_manager\locale\de\LC_MESSAGES\django.po'
    output_file = r'c:\Users\andre\.gemini\antigravity\scratch\ssl_manager\locale\de\LC_MESSAGES\django.po'
    
    translate_po_file(input_file, output_file)
