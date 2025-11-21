#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
German translation script for django.po file - Fixed version
"""

def translate_po_file(input_path, output_path):
    """Translate the .po file with German translations"""
    print(f"Reading {input_path}...")
    
    with open(input_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Translation mapping
    translations = {
        "Select Domain": "Domain auswählen",
        "e.g. app1": "z.B. app1",
        "Certificate File": "Zertifikatsdatei",
        "Upload certificate (.crt, .cer, .pem)": "Zertifikat hochladen (.crt, .cer, .pem)",
        "Administrator": "Administrator",
        "Normal User": "Normaler Benutzer",
        "Number of previous passwords to remember": "Anzahl der zu merkenden vorherigen Passwörter",
        "Pending": "Ausstehend",
        "Issued": "Ausgestellt",
        "Signed": "Signiert",
        "Revoked": "Widerrufen",
        "Session key for anonymous users": "Sitzungsschlüssel für anonyme Benutzer",
        "User if authenticated": "Benutzer wenn authentifiziert",
        "SSL Manager": "SSL-Manager",
        "Logout": "Abmelden",
        "Administration": "Verwaltung",
        "Login": "Anmelden",
        "Learn more": "Mehr erfahren",
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
        "Success!": "Erfolg!",
        "CSR and Private Key for": "CSR und privater Schlüssel für",
        "Certificate Signing Request (CSR)": "Zertifikatsignierungsanforderung (CSR)",
        "Private Key (Keep Secret!)": "Privater Schlüssel (Geheim halten!)",
        "Return Home": "Zur Startseite",
        "Generate Another": "Weitere generieren",
        "Generate New CSR": "Neuen CSR generieren",
        "Domain Information": "Domain-Informationen",
        "Domain": "Domain",
        "Subdomain (App Name)": "Subdomain (App-Name)",
        "e.g., 'app1' for app1.example.com": "z.B. 'app1' für app1.example.com",
        "Generate CSR & Key": "CSR & Schlüssel generieren",
        "Cancel": "Abbrechen",
        "Generate New": "Neu generieren",
        "Create a new CSR and Private Key for your domain.": "Erstellen Sie einen neuen CSR und privaten Schlüssel für Ihre Domain.",
        "Search Repository": "Repository durchsuchen",
        "Find existing certificates, keys, and CSRs.": "Finden Sie vorhandene Zertifikate, Schlüssel und CSRs.",
        "Username": "Benutzername",
        "Password": "Passwort",
        "Sign In": "Anmelden",
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
        "Change Password": "Passwort ändern",
        "Password Requirements:": "Passwortanforderungen:",
        "Minimum 12 characters (16 for Admins)": "Mindestens 12 Zeichen (16 für Administratoren)",
        "Must contain uppercase, lowercase, numbers, and special characters": "Muss Groß-, Kleinbuchstaben, Zahlen und Sonderzeichen enthalten",
        "Cannot reuse any of your last 20 passwords": "Kann keines Ihrer letzten 20 Passwörter wiederverwenden",
        "Expires every 90 days": "Läuft alle 90 Tage ab",
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
    }
    
    # Process lines
    output_lines = []
    i = 0
    translated_count = 0
    
    while i < len(lines):
        line = lines[i]
        
        # Check if this is a msgid line
        if line.startswith('msgid "') and i + 1 < len(lines):
            # Extract the msgid value
            msgid_line = line
            msgid_value = line[7:-2]  # Remove 'msgid "' and '"\n'
            
            # Check if next line is empty msgstr
            next_line = lines[i + 1]
            if next_line.startswith('msgstr ""') and msgid_value in translations:
                # Add the msgid line
                output_lines.append(msgid_line)
                # Add the translated msgstr line
                output_lines.append(f'msgstr "{translations[msgid_value]}"\n')
                translated_count += 1
                i += 2  # Skip both lines
                continue
        
        # Special handling for fuzzy flag and language
        if line == '#, fuzzy\n':
            i += 1  # Skip fuzzy line
            continue
        
        if '"Language: \\n"' in line:
            output_lines.append('"Language: de\\n"\n')
            i += 1
            continue
        
        # Add the line as-is
        output_lines.append(line)
        i += 1
    
    # Write the output
    print(f"Writing to {output_path}...")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.writelines(output_lines)
    
    print(f"Translation completed successfully!")
    print(f"Translated {translated_count} strings")

if __name__ == '__main__':
    input_file = r'c:\Users\andre\.gemini\antigravity\scratch\ssl_manager\locale\de\LC_MESSAGES\django.po.bak'
    output_file = r'c:\Users\andre\.gemini\antigravity\scratch\ssl_manager\locale\de\LC_MESSAGES\django.po'
    
    translate_po_file(input_file, output_file)
