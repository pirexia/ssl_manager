# Translation script for German (DE) locale
# This script reads the django.po file and adds German translations

import re

# German translations dictionary
translations = {
    # Forms
    "Select Domain": "Domain auswählen",
    "e.g. app1": "z.B. app1",
    "Certificate File": "Zertifikatsdatei",
    "Upload certificate (.crt, .cer, .pem)": "Zertifikat hochladen (.crt, .cer, .pem)",
    
    # Models
    "Administrator": "Administrator",
    "Normal User": "Normaler Benutzer",
    "Number of previous passwords to remember": "Anzahl der zu merkenden vorherigen Passwörter",
    "Pending": "Ausstehend",
    "Issued": "Ausgestellt",
    "Signed": "Signiert",
    "Revoked": "Widerrufen",
    "Session key for anonymous users": "Sitzungsschlüssel für anonyme Benutzer",
    "User if authenticated": "Benutzer wenn authentifiziert",
    
    # Base template
    "SSL Manager": "SSL-Manager",
    "Logout": "Abmelden",
    "Administration": "Verwaltung",
    "Login": "Anmelden",
    "Learn more": "Mehr erfahren",
    
    # Certificate detail
    "Details": "Details",
    "Domain:": "Domain:",
    "Created By:": "Erstellt von:",
    "Created At:": "Erstellt am:",
    "Organization:": "Organisation:",
    "Unit:": "Abteilung:",
    "Location:": "Standort:",
    "Download .csr": ".csr herunterladen",
    "Private Key": "Privater Schlüssel",
    "Download .key": ".key herunterladen",
    "Iteration History for": "Iterationsverlauf für",
    "Generated": "Generiert",
    "Status": "Status",
    "Valid From": "Gültig ab",
    "Valid Until": "Gültig bis",
    "Created By": "Erstellt von",
    "Files": "Dateien",
    "Upload Certificate": "Zertifikat hochladen",
    "Current": "Aktuell",
    "View": "Ansehen",
    "Common Name:": "Common Name:",
    "Created:": "Erstellt:",
    "Accepted formats: .crt, .cer, .pem": "Akzeptierte Formate: .crt, .cer, .pem",
    "Download PFX": "PFX herunterladen",
    "Back to Search": "Zurück zur Suche",
    
    # CSR result
    "Success!": "Erfolg!",
    "CSR and Private Key for": "CSR und privater Schlüssel für",
    "Certificate Signing Request (CSR)": "Zertifikatsignierungsanforderung (CSR)",
    "Private Key (Keep Secret!)": "Privater Schlüssel (Geheim halten!)",
    "Return Home": "Zur Startseite",
    "Generate Another": "Weitere generieren",
    
    # Generate CSR
    "Generate New CSR": "Neuen CSR generieren",
    "Domain Information": "Domain-Informationen",
    "Domain": "Domain",
    "Subdomain (App Name)": "Subdomain (App-Name)",
    "e.g., 'app1' for app1.example.com": "z.B. 'app1' für app1.example.com",
    "Generate CSR & Key": "CSR & Schlüssel generieren",
    "Cancel": "Abbrechen",
    
    # Home
    "Generate New": "Neu generieren",
    "Create a new CSR and Private Key for your domain.": "Erstellen Sie einen neuen CSR und privaten Schlüssel für Ihre Domain.",
    "Search Repository": "Repository durchsuchen",
    "Find existing certificates, keys, and CSRs.": "Finden Sie vorhandene Zertifikate, Schlüssel und CSRs.",
    
    # Login
    "Username": "Benutzername",
    "Password": "Passwort",
    "Sign In": "Anmelden",
    
    # MFA
    "Setup Two-Factor Authentication": "Zwei-Faktor-Authentifizierung einrichten",
    "Manual Entry Key:": "Manueller Eingabeschlüssel:",
    "Verify and Enable MFA": "MFA überprüfen und aktivieren",
    "Two-Factor Authentication": "Zwei-Faktor-Authentifizierung",
    "Enter the 6-digit code from your authenticator app": "Geben Sie den 6-stelligen Code aus Ihrer Authenticator-App ein",
    "Authentication Code:": "Authentifizierungscode:",
    "Trust this device for 7 days": "Diesem Gerät für 7 Tage vertrauen",
    "Cookies not accepted:": "Cookies nicht akzeptiert:",
    "Verify": "Überprüfen",
    "Cancel and logout": "Abbrechen und abmelden",
    
    # Password change
    "Change Password": "Passwort ändern",
    "Password Requirements:": "Passwortanforderungen:",
    "Minimum 12 characters (16 for Admins)": "Mindestens 12 Zeichen (16 für Administratoren)",
    "Must contain uppercase, lowercase, numbers, and special characters": "Muss Groß-, Kleinbuchstaben, Zahlen und Sonderzeichen enthalten",
    "Cannot reuse any of your last 20 passwords": "Kann keines Ihrer letzten 20 Passwörter wiederverwenden",
    "Expires every 90 days": "Läuft alle 90 Tage ab",
    
    # Search
    "Search by Common Name (live search)": "Suche nach Common Name (Live-Suche)",
    "Hold Ctrl for multiple domains": "Halten Sie Strg für mehrere Domains gedrückt",
    "All": "Alle",
    "Expiring in 1 Month": "Läuft in 1 Monat ab",
    "Show": "Anzeigen",
    "entries": "Einträge",
    "Common Name": "Common Name",
    "Created": "Erstellt",
    "Expires": "Läuft ab",
    "Actions": "Aktionen",
    "No certificates found.": "Keine Zertifikate gefunden.",
    
    # Django contrib
    "Messages": "Nachrichten",
    "Site Maps": "Sitemaps",
    "Static Files": "Statische Dateien",
    "Syndication": "Syndikation",
    
    # Paginator
    "…": "…",
    "That page number is not an integer": "Diese Seitenzahl ist keine ganze Zahl",
    "That page number is less than 1": "Diese Seitenzahl ist kleiner als 1",
    "That page contains no results": "Diese Seite enthält keine Ergebnisse",
    
    # Validators
    "Enter a valid value.": "Geben Sie einen gültigen Wert ein.",
    "Enter a valid domain name.": "Geben Sie einen gültigen Domainnamen ein.",
    "Enter a valid URL.": "Geben Sie eine gültige URL ein.",
    "Enter a valid integer.": "Geben Sie eine gültige Ganzzahl ein.",
    "Enter a valid email address.": "Geben Sie eine gültige E-Mail-Adresse ein.",
    "Enter a valid "slug" consisting of letters, numbers, underscores or hyphens.": "Geben Sie einen gültigen \"Slug\" ein, der aus Buchstaben, Zahlen, Unterstrichen oder Bindestrichen besteht.",
    "Enter a valid "slug" consisting of Unicode letters, numbers, underscores, or hyphens.": "Geben Sie einen gültigen \"Slug\" ein, der aus Unicode-Buchstaben, Zahlen, Unterstrichen oder Bindestrichen besteht.",
    "IPv4": "IPv4",
    "IPv6": "IPv6",
    "IPv4 or IPv6": "IPv4 oder IPv6",
    "Enter only digits separated by commas.": "Geben Sie nur durch Kommas getrennte Ziffern ein.",
    "Enter a number.": "Geben Sie eine Zahl ein.",
    "Null characters are not allowed.": "Null-Zeichen sind nicht erlaubt.",
    "and": "und",
    "This field cannot be null.": "Dieses Feld darf nicht null sein.",
    "This field cannot be blank.": "Dieses Feld darf nicht leer sein.",
    "Boolean (Either True or False)": "Boolean (Entweder Wahr oder Falsch)",
    "String (unlimited)": "Zeichenkette (unbegrenzt)",
    "Comma-separated integers": "Durch Kommas getrennte Ganzzahlen",
    "Date (without time)": "Datum (ohne Uhrzeit)",
    "Date (with time)": "Datum (mit Uhrzeit)",
    "Decimal number": "Dezimalzahl",
    "Duration": "Dauer",
    "Email address": "E-Mail-Adresse",
    "File path": "Dateipfad",
    "Floating point number": "Gleitkommazahl",
    "Integer": "Ganzzahl",
    "Big (8 byte) integer": "Große (8 Byte) Ganzzahl",
    "Small integer": "Kleine Ganzzahl",
    "IPv4 address": "IPv4-Adresse",
    "IP address": "IP-Adresse",
    "Boolean (Either True, False or None)": "Boolean (Entweder Wahr, Falsch oder Keine)",
    "Positive big integer": "Positive große Ganzzahl",
    "Positive integer": "Positive Ganzzahl",
    "Positive small integer": "Positive kleine Ganzzahl",
    "Text": "Text",
    "Time": "Zeit",
    "URL": "URL",
    "Raw binary data": "Rohe Binärdaten",
    "Universally unique identifier": "Universell eindeutiger Bezeichner",
}

def translate_po_file(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Update header
    content = content.replace('#, fuzzy', '')
    content = content.replace('"Language: \\n"', '"Language: de\\n"')
    
    # Translate each msgid
    for english, german in translations.items():
        # Escape special characters for regex
        escaped_english = re.escape(english)
        # Find msgid and replace empty msgstr
        pattern = f'msgid "{escaped_english}"\\r?\\nmsgstr ""'
        replacement = f'msgid "{english}"\\nmsgstr "{german}"'
        content = re.sub(pattern, replacement, content)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Translation completed! Output written to {output_file}")

if __name__ == "__main__":
    input_file = r"c:\Users\andre\.gemini\antigravity\scratch\ssl_manager\locale\de\LC_MESSAGES\django.po"
    output_file = r"c:\Users\andre\.gemini\antigravity\scratch\ssl_manager\locale\de\LC_MESSAGES\django.po"
    translate_po_file(input_file, output_file)
