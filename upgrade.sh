#!/bin/bash

# SSL Manager Upgrade Script

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

INSTALL_DIR="/opt/ssl_manager"

if [ ! -d "$INSTALL_DIR" ]; then
    error "Installation directory $INSTALL_DIR not found. Is the application installed?"
    exit 1
fi

cd $INSTALL_DIR

log "Pulling latest changes from Git..."
git fetch --tags
git pull origin master

# Check if a specific version tag is provided
if [ -n "$1" ]; then
    log "Switching to version $1..."
    git checkout $1
fi

log "Activating virtual environment..."
source venv/bin/activate

log "Updating Python dependencies..."
pip install -r requirements.txt

log "Applying database migrations..."
python manage.py migrate

log "Collecting static files..."
python manage.py collectstatic --noinput

log "Restarting ssl_manager service..."
systemctl restart ssl_manager

success "Upgrade Complete!"
echo "Current version:"
git describe --tags --always
