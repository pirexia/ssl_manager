# SSL Manager

**SSL Manager** is a robust, Django-based web application designed to simplify the lifecycle management of SSL/TLS certificates. It provides a centralized platform for generating Certificate Signing Requests (CSRs), managing private keys securely, and acting as an Internal Certificate Authority (CA) for development and testing environments.

## 🚀 Features

-   **CSR Generation**: Easy-to-use wizard for generating OpenSSL-standard CSRs and Private Keys (RSA 2048/4096).
-   **Internal CA**: Built-in Root CA to sign certificates internally for dev/test use.
-   **Certificate Management**: Upload, store, and organize certificates (.crt, .cer, .pem, .pfx).
-   **Security**:
    -   **MFA**: Multi-Factor Authentication (TOTP) support.
    -   **LDAP/AD**: Integration with Active Directory/LDAP for user authentication.
    -   **RBAC**: Role-based access control (Admin/User).
-   **Internationalization**: Available in English, Spanish, Portuguese, French, German, and Italian.

## 📚 Documentation

Full documentation is available in the `docs/` directory:

-   **[Installation Guide](docs/Installation.md)**: Step-by-step instructions for deploying on Linux (RHEL9/Debian).
-   **[User Manual](docs/UserManual.md)**: Comprehensive guide on using the application features.
-   **[Wiki Home](docs/Home.md)**: Index of all documentation.

## 🛠️ Quick Start

To install SSL Manager on a fresh Linux server:

```bash
git clone https://github.com/pirexia/ssl_manager.git
cd ssl_manager
chmod +x install.sh
sudo ./install.sh
```

For detailed instructions, please refer to the [Installation Guide](docs/Installation.md).

## 🔄 Upgrading

To upgrade an existing installation:

```bash
sudo ./upgrade.sh
```

## License

[MIT License](LICENSE)
