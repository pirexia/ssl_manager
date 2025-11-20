# MFA Implementation Plan

## Goal
Implement Multi-Factor Authentication (MFA) using Time-based One-Time Passwords (TOTP). This will allow users to secure their accounts using authenticator apps like Google Authenticator or Microsoft Authenticator.

## User Review Required
> [!IMPORTANT]
> **Library Choice**: We will use `django-otp` and `qrcode` as they are the standard for Django MFA.
> **Enforcement**: Should MFA be mandatory for ALL users, only Admins, or optional?
> *Assumption for now*: Optional for Users, Mandatory for Admins (can be configured).

## Proposed Changes

### Dependencies
- Add `django-otp` and `qrcode` to `requirements.txt`.

### Settings (`ssl_manager/settings.py`)
- Add `django_otp` and `django_otp.plugins.otp_totp` to `INSTALLED_APPS`.
- Add `django_otp.middleware.OTPMiddleware` to `MIDDLEWARE`.

### Models
- `django-otp` handles models (TOTPDevice).
- **[NEW] `TrustedDevice`**:
    - `user` (ForeignKey to User)
    - `token` (Secure random string, unique)
    - `expires_at` (DateTimeField)
    - `user_agent` (To identify device in UI)
    - `last_used` (DateTimeField)

### Views (`certificates/views.py`)
#### [NEW] `mfa_setup`
- Generate a TOTP device for the user.
- Generate QR code for the device config URL.
- Render page with QR code and text key.

#### [NEW] `mfa_verify`
- Verify the token provided by the user to confirm setup.

#### [NEW] `mfa_login`
- Intercept login flow.
- **Trusted Device Check**:
    1. Check for `trusted_device` cookie.
    2. Validate token against `TrustedDevice` table.
    3. If valid and not expired (7 days), skip TOTP.
- If TOTP required:
    - Show form with "Trust this computer for 7 days" checkbox.
    - On success:
        - If checked, create `TrustedDevice` record (expires in 7 days).
        - Set secure, HTTP-only cookie with token.

### Templates
- `templates/mfa/setup.html`: QR code display.
- `templates/mfa/verify.html`: Token input form with "Trust this device" checkbox.

## Verification Plan
1. **Setup**: Log in, go to MFA setup, scan QR code.
2. **Trusted Login**:
    - Log out.
    - Log in, check "Trust this device".
    - Enter TOTP.
    - Verify login success and cookie set.
3. **Skip TOTP**:
    - Log out.
    - Log in again.
    - Verify TOTP step is SKIPPED.
4. **Expiration**:
    - Manually expire the `TrustedDevice` record in DB.
    - Log out and in.
    - Verify TOTP is REQUIRED again.
