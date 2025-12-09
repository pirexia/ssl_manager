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
    PKG_LDAP="openldap-devel"
elif [ -f /etc/debian_version ]; then
    OS="debian"
    PKG_MANAGER="apt-get"
    PKG_PYTHON="python3-dev"
    PKG_GCC="gcc"
    PKG_MYSQL="libmysqlclient-dev"
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
        read -p "Database Host [localhost]: " DB_HOST
        read -p "Database Port [3306]: " DB_PORT
        read -p "Database Name [ssl_manager]: " DB_NAME
        read -p "Database User [ssl_user]: " DB_USER
        read -s -p "Database Password: " DB_PASSWORD
        echo ""

        echo "DB_HOST=${DB_HOST:-localhost}" >> .env
        echo "DB_PORT=${DB_PORT:-3306}" >> .env
        echo "DB_NAME=${DB_NAME:-ssl_manager}" >> .env
        echo "DB_USER=${DB_USER:-ssl_user}" >> .env
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
