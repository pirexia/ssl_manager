# Implementation Plan - SSL Certificate Manager

## Goal Description
Build a web-based SSL Certificate Manager using Python/Django. The application will allow users to generate CSRs (Certificate Signing Requests) and Private Keys, store them, and manage the lifecycle of SSL certificates. It will feature role-based access control (Admin/User), password policies, and a search interface.

## User Review Required
> [!IMPORTANT]
> **Database**: We will use SQLite for development to speed up the process, but the production environment will require MariaDB. The `settings.py` will need to be configured for MariaDB in production.
> **Security**: Private keys will be stored in the database. We must ensure the database is encrypted or access is strictly controlled. For this MVP, we will store them as text/blob fields, but in a real production scenario, field-level encryption is recommended.

## Proposed Changes

### Environment & Setup
#### [NEW] [requirements.txt](file:///c:/Users/andre/.gemini/antigravity/scratch/ssl_manager/requirements.txt)
- django
- cryptography (for CSR/Key generation)
- mysqlclient (for MariaDB support)

### Backend - Django Core
#### [NEW] [manage.py](file:///c:/Users/andre/.gemini/antigravity/scratch/ssl_manager/manage.py)
- Standard Django entry point.

#### [NEW] [ssl_manager/settings.py](file:///c:/Users/andre/.gemini/antigravity/scratch/ssl_manager/ssl_manager/settings.py)
- Configuration for Apps, Database, Static files.
- Custom User Model configuration.

#### [NEW] [certificates/models.py](file:///c:/Users/andre/.gemini/antigravity/scratch/ssl_manager/certificates/models.py)
- `User`: Custom user model extending AbstractUser.
- `Role`: Model for user roles (Admin, User).
- `PasswordPolicy`: Model to store complexity rules.
- `Domain`: Model for allowed domains (e.g., example.com).
- `CertificateEntry`: Model to store Common Name, CSR, Private Key, Certificate content, Status, requester, etc.

#### [NEW] [certificates/views.py](file:///c:/Users/andre/.gemini/antigravity/scratch/ssl_manager/certificates/views.py)
- `home`: Landing page with "Generate" and "Search" buttons.
- `generate_csr`: Wizard to select domain, input subdomain, generate CSR/Key.
- `search_certificates`: Search view with dynamic filtering.
- `certificate_detail`: View details, edit, delete.
- `admin_panel`: Custom admin dashboard for managing domains and users.

#### [NEW] [certificates/utils.py](file:///c:/Users/andre/.gemini/antigravity/scratch/ssl_manager/certificates/utils.py)
- Helper functions for OpenSSL/Cryptography interactions (Generate Key, Generate CSR).

### Frontend
#### [NEW] [templates/base.html](file:///c:/Users/andre/.gemini/antigravity/scratch/ssl_manager/templates/base.html)
- Main layout with Navbar (User info, Logout, Admin settings).

#### [NEW] [templates/home.html](file:///c:/Users/andre/.gemini/antigravity/scratch/ssl_manager/templates/home.html)
- Two large buttons: Generate vs Search.

#### [NEW] [templates/generate_csr.html](file:///c:/Users/andre/.gemini/antigravity/scratch/ssl_manager/templates/generate_csr.html)
- Form for CSR generation.

#### [NEW] [templates/search.html](file:///c:/Users/andre/.gemini/antigravity/scratch/ssl_manager/templates/search.html)
- Search results list.

## Verification Plan

### Automated Tests
- Run `python manage.py test` to verify model constraints and cryptographic functions.

### Manual Verification
1.  **Setup**: Run migrations, create superuser.
2.  **Login**: Test login with different roles.
3.  **Generate**: Create a CSR for `app1.example.com`. Verify CSR and Key are generated and downloadable.
4.  **Search**: Search for `app1`. Verify the record appears.
5.  **Admin**: Go to settings, add a new Domain. Verify it appears in the dropdown.
