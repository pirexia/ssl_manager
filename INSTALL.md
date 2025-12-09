# SSL Manager - Installation Guide

This guide provides step-by-step instructions to install and configure the SSL Manager application on a Linux server (RHEL9/CentOS 9 or Debian/Ubuntu).

## Prerequisites

Before starting, ensure you have:
- **Root access** (sudo) to the server.
- **Git** installed to clone the repository.
- **Internet access** to install system packages and Python dependencies.

## 1. Clone the Repository

First, download the application source code from the Git repository.

```bash
cd /opt
git clone <YOUR_REPOSITORY_URL> ssl_manager
cd ssl_manager
```
*(Replace `<YOUR_REPOSITORY_URL>` with the actual URL of your git repo)*

## 2. Run the Installer

The included `install.sh` script automates the installation process, including:
- Installing system dependencies (Python, GCC, MariaDB/MySQL libs, LDAP libs).
- Setting up a Python virtual environment.
- Installing Python libraries.
- Configuring the database (SQLite or MySQL/MariaDB).
- Creating the initial admin user.
- Setting up a Systemd service.

Make the script executable and run it:

```bash
chmod +x install.sh
sudo ./install.sh
```

### Interactive Configuration
During installation, you will be prompted for:
1.  **Database Engine**:
    - Choose `1` for **SQLite** (easiest, good for testing).
    - Choose `2` for **MySQL/MariaDB** (recommended for production).
2.  **Database Credentials** (if MySQL is selected):
    - Host, Port, Name, User, Password.
3.  **Create Admin User**:
    - Choose `y` to create the initial superuser for logging in.
4.  **Load Example Data**:
    - Choose `y` to load default Roles (Admin/User) and an example domain.

## 3. Manage the Service

The installer creates a systemd service named `ssl_manager`.

**Start the service:**
```bash
sudo systemctl start ssl_manager
```

**Enable auto-start on boot:**
```bash
sudo systemctl enable ssl_manager
```

**Check status:**
```bash
sudo systemctl status ssl_manager
```

## 4. Access the Application

Open your web browser and navigate to:
`http://<YOUR_SERVER_IP>:8000`

Login with the admin credentials you created during installation.

## Troubleshooting

### Database Connection Errors
If using MySQL/MariaDB, ensure the database exists and the user has permissions:
```sql
CREATE DATABASE ssl_manager CHARACTER SET utf8mb4;
CREATE USER 'ssl_user'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON ssl_manager.* TO 'ssl_user'@'localhost';
FLUSH PRIVILEGES;
```
Check the `.env` file in the application directory to verify your settings.

### LDAP Issues
If you need to configure LDAP, edit the `ssl_manager/settings.py` file or add LDAP variables to `.env` (requires manual configuration in `settings.py` to fully utilize env vars for LDAP if not already set).

### Manual Installation (If script fails)
1.  Install dependencies: `python3-devel`, `gcc`, `mariadb-devel`, `openldap-devel`.
2.  Create venv: `python3 -m venv venv && source venv/bin/activate`.
3.  Install libs: `pip install -r requirements.txt`.
4.  Configure `.env` (copy from `install.sh` logic).
5.  Run migrations: `python manage.py migrate`.
6.  Run server: `gunicorn ssl_manager.wsgi:application --bind 0.0.0.0:8000`.
