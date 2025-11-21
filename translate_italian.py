#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Italian translation script for django.po file
"""

def translate_po_file(input_path, output_path):
    """Translate the .po file with Italian translations"""
    print(f"Reading {input_path}...")
    
    with open(input_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Translation mapping - Italian
    translations = {
        "Select Domain": "Seleziona Dominio",
        "e.g. app1": "es. app1",
        "Certificate File": "File Certificato",
        "Upload certificate (.crt, .cer, .pem)": "Carica certificato (.crt, .cer, .pem)",
        "Administrator": "Amministratore",
        "Normal User": "Utente Normale",
        "Number of previous passwords to remember": "Numero di password precedenti da ricordare",
        "Pending": "In Attesa",
        "Issued": "Emesso",
        "Signed": "Firmato",
        "Revoked": "Revocato",
        "Session key for anonymous users": "Chiave di sessione per utenti anonimi",
        "User if authenticated": "Utente se autenticato",
        "SSL Manager": "Gestore SSL",
        "Logout": "Disconnetti",
        "Administration": "Amministrazione",
        "Login": "Accedi",
        "Learn more": "Scopri di più",
        "Details": "Dettagli",
        "Domain:": "Dominio:",
        "Created By:": "Creato Da:",
        "Created At:": "Creato Il:",
        "Organization:": "Organizzazione:",
        "Unit:": "Unità:",
        "Location:": "Posizione:",
        "Download .csr": "Scarica .csr",
        "Private Key": "Chiave Privata",
        "Download .key": "Scarica .key",
        "Iteration History for": "Cronologia Iterazioni per",
        "Generated": "Generato",
        "Status": "Stato",
        "Valid From": "Valido Da",
        "Valid Until": "Valido Fino",
        "Created By": "Creato Da",
        "Files": "File",
        "Upload Certificate": "Carica Certificato",
        "Current": "Corrente",
        "View": "Visualizza",
        "Common Name:": "Nome Comune:",
        "Created:": "Creato:",
        "Accepted formats: .crt, .cer, .pem": "Formati accettati: .crt, .cer, .pem",
        "Download PFX": "Scarica PFX",
        "Back to Search": "Torna alla Ricerca",
        "Success!": "Successo!",
        "CSR and Private Key for": "CSR e Chiave Privata per",
        "Certificate Signing Request (CSR)": "Richiesta di Firma del Certificato (CSR)",
        "Private Key (Keep Secret!)": "Chiave Privata (Mantieni Segreto!)",
        "Return Home": "Torna alla Home",
        "Generate Another": "Genera un Altro",
        "Generate New CSR": "Genera Nuovo CSR",
        "Domain Information": "Informazioni Dominio",
        "Domain": "Dominio",
        "Subdomain (App Name)": "Sottodominio (Nome App)",
        "e.g., 'app1' for app1.example.com": "es. 'app1' per app1.example.com",
        "Generate CSR & Key": "Genera CSR e Chiave",
        "Cancel": "Annulla",
        "Generate New": "Genera Nuovo",
        "Create a new CSR and Private Key for your domain.": "Crea un nuovo CSR e Chiave Privata per il tuo dominio.",
        "Search Repository": "Cerca nel Repository",
        "Find existing certificates, keys, and CSRs.": "Trova certificati, chiavi e CSR esistenti.",
        "Username": "Nome Utente",
        "Password": "Password",
        "Sign In": "Accedi",
        "Setup Two-Factor Authentication": "Configura Autenticazione a Due Fattori",
        "Manual Entry Key:": "Chiave di Inserimento Manuale:",
        "Verify and Enable MFA": "Verifica e Abilita MFA",
        "Two-Factor Authentication": "Autenticazione a Due Fattori",
        "Enter the 6-digit code from your authenticator app": "Inserisci il codice a 6 cifre dalla tua app di autenticazione",
        "Authentication Code:": "Codice di Autenticazione:",
        "Trust this device for 7 days": "Considera attendibile questo dispositivo per 7 giorni",
        "Cookies not accepted:": "Cookie non accettati:",
        "Verify": "Verifica",
        "Cancel and logout": "Annulla e disconnetti",
        "Change Password": "Cambia Password",
        "Password Requirements:": "Requisiti Password:",
        "Minimum 12 characters (16 for Admins)": "Minimo 12 caratteri (16 per Amministratori)",
        "Must contain uppercase, lowercase, numbers, and special characters": "Deve contenere maiuscole, minuscole, numeri e caratteri speciali",
        "Cannot reuse any of your last 20 passwords": "Non può riutilizzare nessuna delle ultime 20 password",
        "Expires every 90 days": "Scade ogni 90 giorni",
        "Search by Common Name (live search)": "Cerca per Nome Comune (ricerca in tempo reale)",
        "Hold Ctrl for multiple domains": "Tieni premuto Ctrl per più domini",
        "All": "Tutti",
        "Expiring in 1 Month": "In Scadenza tra 1 Mese",
        "Show": "Mostra",
        "entries": "voci",
        "Common Name": "Nome Comune",
        "Created": "Creato",
        "Expires": "Scade",
        "Actions": "Azioni",
        "No certificates found.": "Nessun certificato trovato.",
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
            output_lines.append('"Language: it\\n"\n')
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
    input_file = r'c:\Users\andre\.gemini\antigravity\scratch\ssl_manager\locale\it\LC_MESSAGES\django.po.bak'
    output_file = r'c:\Users\andre\.gemini\antigravity\scratch\ssl_manager\locale\it\LC_MESSAGES\django.po'
    
    translate_po_file(input_file, output_file)
