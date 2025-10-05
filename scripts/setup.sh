#!/bin/bash

# AI-Driven WAF Setup Script
# This script sets up the WAF environment and dependencies

set -e

echo "🛡️  Setting up AI-Driven WAF..."

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should not be run as root for security reasons"
   exit 1
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p logs models config data monitoring/grafana monitoring/prometheus

# Create virtual environment
echo "🐍 Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Create .env file from example if it doesn't exist
if [ ! -f .env ]; then
    echo "⚙️  Creating .env file from template..."
    cp .env.example .env
    echo "✏️  Please edit .env file with your configuration"
fi

# Set up database (PostgreSQL)
echo "🗄️  Setting up database..."
if command -v psql &> /dev/null; then
    echo "Creating WAF database..."
    sudo -u postgres createdb waf_db 2>/dev/null || echo "Database may already exist"
    sudo -u postgres psql -c "CREATE USER waf_user WITH PASSWORD 'waf_pass';" 2>/dev/null || echo "User may already exist"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE waf_db TO waf_user;" 2>/dev/null || echo "Privileges may already be granted"
else
    echo "⚠️  PostgreSQL not found. Please install PostgreSQL and run this script again."
fi

# Set up Redis
echo "🔴 Checking Redis..."
if command -v redis-server &> /dev/null; then
    echo "✅ Redis found"
    # Start Redis if not running
    if ! pgrep -x "redis-server" > /dev/null; then
        echo "Starting Redis..."
        redis-server --daemonize yes
    fi
else
    echo "⚠️  Redis not found. Please install Redis and run this script again."
fi

# Set up system dependencies for packet capture
echo "🌐 Setting up network capabilities..."
if command -v setcap &> /dev/null; then
    echo "Setting network capabilities for Python..."
    sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
else
    echo "⚠️  setcap not found. You may need to run the WAF as root for packet capture."
fi

# Download sample threat intelligence feeds
echo "🔍 Setting up threat intelligence..."
mkdir -p data/threat_feeds
curl -s "https://rules.emergingthreats.net/open/suricata/rules/emerging-malware.rules" > data/threat_feeds/emerging-malware.rules 2>/dev/null || echo "Could not download sample threat feed"

# Set up monitoring
echo "📊 Setting up monitoring..."
mkdir -p monitoring/prometheus monitoring/grafana

# Create Prometheus config
cp config/prometheus.yml monitoring/prometheus/ 2>/dev/null || echo "Prometheus config already exists"

# Set up log rotation
echo "📝 Setting up log rotation..."
sudo tee /etc/logrotate.d/waf << EOF
/path/to/waf/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $USER $USER
    postrotate
        systemctl reload waf || true
    endscript
}
EOF

# Create systemd service file
echo "🔧 Creating systemd service..."
sudo tee /etc/systemd/system/waf.service << EOF
[Unit]
Description=AI-Driven WAF
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
Environment=PATH=$(pwd)/venv/bin
ExecStart=$(pwd)/venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable but don't start the service yet
sudo systemctl daemon-reload
sudo systemctl enable waf

# Set up firewall rules (optional)
echo "🔥 Setting up firewall rules..."
if command -v ufw &> /dev/null; then
    echo "Configuring UFW firewall..."
    sudo ufw allow 8000/tcp comment "WAF API"
    sudo ufw allow 8080/tcp comment "WAF Dashboard"
    sudo ufw allow 9090/tcp comment "Prometheus Metrics"
else
    echo "⚠️  UFW not found. Please configure firewall manually."
fi

# Create sample configuration files
echo "📋 Creating sample configurations..."

# Create sample ML training data directory
mkdir -p data/training/benign data/training/malicious

# Create sample network segments configuration
cat > config/network_segments.json << EOF
{
    "trusted": ["10.0.1.0/24", "192.168.1.0/24"],
    "dmz": ["10.0.2.0/24"],
    "quarantine": ["10.0.99.0/24"],
    "guest": ["10.0.100.0/24"]
}
EOF

# Create sample MITRE ATT&CK mapping
cat > config/mitre_mapping.json << EOF
{
    "SQL_INJECTION": ["T1190"],
    "XSS": ["T1190"],
    "COMMAND_INJECTION": ["T1059"],
    "MALWARE": ["T1055", "T1071"],
    "BRUTE_FORCE": ["T1110"],
    "ANOMALY": ["T1083", "T1087"]
}
EOF

echo "✅ WAF setup completed!"
echo ""
echo "🚀 Next steps:"
echo "1. Edit .env file with your configuration"
echo "2. Start the services: sudo systemctl start waf"
echo "3. Access the dashboard at http://localhost:8080"
echo "4. Access the API at http://localhost:8000/api/docs"
echo "5. Monitor metrics at http://localhost:9090"
echo ""
echo "📚 Documentation: See README.md for detailed usage instructions"
echo "🔒 Security: Remember to change default passwords and keys in production!"