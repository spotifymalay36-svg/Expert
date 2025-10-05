#!/bin/bash

# AI-Driven WAF Startup Script

set -e

echo "🛡️  Starting AI-Driven WAF..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup.sh first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "❌ .env file not found. Please copy .env.example to .env and configure it."
    exit 1
fi

# Check dependencies
echo "🔍 Checking dependencies..."

# Check Redis
if ! redis-cli ping > /dev/null 2>&1; then
    echo "⚠️  Redis is not running. Starting Redis..."
    redis-server --daemonize yes
    sleep 2
fi

# Check PostgreSQL
if ! pg_isready -h localhost -p 5432 > /dev/null 2>&1; then
    echo "⚠️  PostgreSQL is not running. Please start PostgreSQL service."
    exit 1
fi

# Create necessary directories
mkdir -p logs models data/threat_feeds

# Set network capabilities if needed
if [ "$EUID" -ne 0 ]; then
    echo "🌐 Checking network capabilities..."
    if ! getcap $(which python3) | grep -q "cap_net_raw"; then
        echo "⚠️  Network capabilities not set. You may need to run with sudo for packet capture."
        echo "   Or run: sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)"
    fi
fi

# Start background services
echo "🚀 Starting background services..."

# Start Prometheus if available
if command -v prometheus &> /dev/null && [ -f "monitoring/prometheus/prometheus.yml" ]; then
    echo "📊 Starting Prometheus..."
    prometheus --config.file=monitoring/prometheus/prometheus.yml --storage.tsdb.path=monitoring/prometheus/data --web.console.libraries=monitoring/prometheus/console_libraries --web.console.templates=monitoring/prometheus/consoles &
    PROMETHEUS_PID=$!
    echo $PROMETHEUS_PID > logs/prometheus.pid
fi

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down WAF..."
    
    # Kill background processes
    if [ -f "logs/prometheus.pid" ]; then
        kill $(cat logs/prometheus.pid) 2>/dev/null || true
        rm -f logs/prometheus.pid
    fi
    
    echo "✅ WAF shutdown complete"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Start the main WAF application
echo "🛡️  Starting WAF Engine..."
echo "   API will be available at: http://localhost:8000"
echo "   Dashboard will be available at: http://localhost:8080"
echo "   Metrics will be available at: http://localhost:9090"
echo ""
echo "Press Ctrl+C to stop the WAF"
echo ""

# Start the application
python main.py

# This line should not be reached due to the signal handlers
cleanup