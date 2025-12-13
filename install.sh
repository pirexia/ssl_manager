#!/bin/bash

# SSL Manager Installer
# Supports RHEL/CentOS/Fedora and Debian/Ubuntu

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for root
if [ "$EUID" -ne 0 ]; then
  error "Please run as root"
  exit 1
fi

# Detect OS
if [ -f /etc/redhat-release ]; then
    OS="rhel"
    PKG_MANAGER="dnf"
    PKG_PYTHON="python3-devel"
    PKG_GCC="gcc"
    PKG_MYSQL="mariadb-devel"
    PKG_MYSQL_SERVER="mariadb-server"
    PKG_LDAP="openldap-devel"
elif [ -f /etc/debian_version ]; then
    OS="debian"
    PKG_MANAGER="apt-get"
    PKG_PYTHON="python3-dev"
    PKG_GCC="gcc"
    PKG_MYSQL="libmysqlclient-dev"
    PKG_MYSQL_SERVER="mariadb-server"
    PKG_LDAP="libsasl2-dev libldap2-dev libssl-dev"
else
    error "Unsupported OS. Only RHEL/CentOS and Debian/Ubuntu are supported."
    exit 1
fi

log "Detected OS: $OS"

# Install System Dependencies
log "Installing system dependencies..."
if [ "$OS" == "rhel" ]; then
    $PKG_MANAGER install -y $PKG_PYTHON $PKG_GCC $PKG_MYSQL $PKG_LDAP git
else
    $PKG_MANAGER update
    $PKG_MANAGER install -y $PKG_PYTHON $PKG_GCC $PKG_MYSQL $PKG_LDAP git python3-venv
fi

# Setup Directory
INSTALL_DIR="/opt/ssl_manager"
if [ ! -d "$INSTALL_DIR" ]; then
    log "Creating installation directory at $INSTALL_DIR..."
    mkdir -p $INSTALL_DIR
    # Assuming we are running from the git repo, copy files
    cp -r . $INSTALL_DIR
else
    log "Directory $INSTALL_DIR already exists. Updating..."
    cp -r . $INSTALL_DIR
fi

cd $INSTALL_DIR

# Setup Virtual Environment
log "Setting up virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

log "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Configuration
log "Configuring application..."
if [ ! -f ".env" ]; then
    echo "Creating .env file..."

    # Generate Secret Key
    SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')

    echo "SECRET_KEY=$SECRET_KEY" > .env
    echo "DEBUG=False" >> .env
    echo "ALLOWED_HOSTS=*" >> .env

    # Database Selection
    echo ""
    echo "Select Database Engine:"
    echo "1) SQLite (Simple, file-based)"
    echo "2) MySQL / MariaDB (Recommended for production)"
    read -p "Enter choice [1]: " DB_CHOICE
    DB_CHOICE=${DB_CHOICE:-1}

    if [ "$DB_CHOICE" == "2" ]; then
        echo "DB_ENGINE=mysql" >> .env

        echo ""
        echo "Database Location:"
        echo "1) Local (Same Server)"
        echo "2) Remote"
        read -p "Enter choice [1]: " DB_LOC_CHOICE
        DB_LOC_CHOICE=${DB_LOC_CHOICE:-1}

        DB_HOST_VAL="localhost"
        DB_PORT_VAL="3306"
        DB_NAME_VAL="ssl_manager"
        DB_USER_VAL="ssl_user"
        DB_PASS_VAL=""

        if [ "$DB_LOC_CHOICE" == "1" ]; then
            # Local Database
            DB_HOST_VAL="localhost"

            # Check if MySQL/MariaDB is installed
            log "Checking for local database server..."
            if command -v mysql >/dev/null 2>&1 || systemctl list-units --full -all | grep -Fq "mariadb.service"; then
                log "Local database server detected."

                echo "--------------------------------------------------------"
                echo "Please execute the following commands in your MySQL client to prepare the database:"
                echo "1. Log in to MySQL as root: mysql -u root -p"
                echo "2. Run:"
                echo "   CREATE DATABASE ssl_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
                echo "   CREATE USER 'ssl_user'@'localhost' IDENTIFIED BY 'YOUR_PASSWORD';"
                echo "   GRANT ALL PRIVILEGES ON ssl_manager.* TO 'ssl_user'@'localhost';"
                echo "   FLUSH PRIVILEGES;"
                echo "--------------------------------------------------------"
                read -p "Press Enter once you have created the database and user..."
            else
                log "Local database server NOT detected. Installing MariaDB Server..."

                if [ "$OS" == "rhel" ]; then
                    $PKG_MANAGER install -y $PKG_MYSQL_SERVER
                else
                    export DEBIAN_FRONTEND=noninteractive
                    $PKG_MANAGER install -y $PKG_MYSQL_SERVER
                fi

                log "Starting MariaDB service..."
                systemctl enable --now mariadb

                # Auto-configure option
                echo ""
                read -p "Automatically create database and user (ssl_manager / ssl_user)? [Y/n]: " AUTO_DB
                if [[ ! "$AUTO_DB" =~ ^[Nn]$ ]]; then
                    GEN_DB_PASS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')
                    log "Configuring database..."
                    mysql -e "CREATE DATABASE IF NOT EXISTS ssl_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
                    mysql -e "CREATE USER IF NOT EXISTS 'ssl_user'@'localhost' IDENTIFIED BY '$GEN_DB_PASS';"
                    mysql -e "GRANT ALL PRIVILEGES ON ssl_manager.* TO 'ssl_user'@'localhost';"
                    mysql -e "FLUSH PRIVILEGES;"

                    DB_NAME_VAL="ssl_manager"
                    DB_USER_VAL="ssl_user"
                    DB_PASS_VAL="$GEN_DB_PASS"

                    success "Database created with password: $GEN_DB_PASS"
                else
                    echo "Skipping auto-configuration. Please create the database manually."
                fi
            fi
        fi

        # Connection Details
        echo ""
        read -p "Database Host [$DB_HOST_VAL]: " DB_HOST
        read -p "Database Port [$DB_PORT_VAL]: " DB_PORT
        read -p "Database Name [$DB_NAME_VAL]: " DB_NAME
        read -p "Database User [$DB_USER_VAL]: " DB_USER

        if [ -n "$DB_PASS_VAL" ]; then
            echo "Using generated password."
            DB_PASSWORD="$DB_PASS_VAL"
        else
            read -s -p "Database Password: " DB_PASSWORD
            echo ""
        fi

        echo "DB_HOST=${DB_HOST:-$DB_HOST_VAL}" >> .env
        echo "DB_PORT=${DB_PORT:-$DB_PORT_VAL}" >> .env
        echo "DB_NAME=${DB_NAME:-$DB_NAME_VAL}" >> .env
        echo "DB_USER=${DB_USER:-$DB_USER_VAL}" >> .env
        echo "DB_PASSWORD=$DB_PASSWORD" >> .env
    else
        echo "DB_ENGINE=sqlite3" >> .env
    fi
else
    log ".env file already exists. Skipping configuration."
fi

# Database Initialization
log "Initializing database..."
python manage.py migrate

# Create Admin User
echo ""
read -p "Create admin user? [y/N]: " CREATE_ADMIN
if [[ "$CREATE_ADMIN" =~ ^[Yy]$ ]]; then
    python manage.py createsuperuser
fi

# Load Initial Data
echo ""
read -p "Load example data (Roles, Domain)? [y/N]: " LOAD_DATA
if [[ "$LOAD_DATA" =~ ^[Yy]$ ]]; then
    python manage.py loaddata fixtures/initial_data.json
fi

# Collect Static Files
log "Collecting static files..."
python manage.py collectstatic --noinput

# Systemd Service
log "Creating systemd service..."
cat > /etc/systemd/system/ssl_manager.service <<EOF
[Unit]
Description=SSL Manager Gunicorn Service
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/gunicorn --access-logfile - --workers 3 --bind 0.0.0.0:8000 ssl_manager.wsgi:application

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

success "Installation Complete!"
echo "To start the service, run: systemctl start ssl_manager"
echo "To enable on boot, run: systemctl enable ssl_manager"
