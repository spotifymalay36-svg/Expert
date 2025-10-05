# 🚀 Deployment Guide

## Overview

This guide covers various deployment scenarios for the AI-Driven WAF, from development environments to production-ready enterprise deployments.

## Prerequisites

### System Requirements

#### Minimum Requirements (Development)
- **CPU**: 4 cores (2.0 GHz+)
- **RAM**: 8 GB
- **Storage**: 100 GB SSD
- **Network**: 1 Gbps
- **OS**: Ubuntu 20.04+, CentOS 8+, or RHEL 8+

#### Recommended Requirements (Production)
- **CPU**: 16 cores (3.0 GHz+)
- **RAM**: 32 GB
- **Storage**: 500 GB NVMe SSD
- **Network**: 10 Gbps+
- **OS**: Ubuntu 22.04 LTS or RHEL 9

#### Enterprise Requirements (High Availability)
- **CPU**: 32+ cores per node
- **RAM**: 64+ GB per node
- **Storage**: 1+ TB NVMe SSD per node
- **Network**: 25+ Gbps with redundancy
- **Nodes**: 3+ instances for HA

### Software Dependencies
- Python 3.11+
- PostgreSQL 14+
- Redis 6.2+
- Docker 20.10+ (optional)
- Kubernetes 1.24+ (for container deployment)

## Deployment Methods

### 1. Local Development Deployment

#### Quick Start
```bash
# Clone repository
git clone https://github.com/your-org/ai-driven-waf.git
cd ai-driven-waf

# Run setup
chmod +x scripts/setup.sh
./scripts/setup.sh

# Start WAF
chmod +x scripts/start.sh
./scripts/start.sh
```

#### Manual Setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Setup databases
sudo -u postgres createdb waf_db
sudo -u postgres psql -c "CREATE USER waf_user WITH PASSWORD 'waf_pass';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE waf_db TO waf_user;"

# Start Redis
redis-server --daemonize yes

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start application
python main.py
```

### 2. Docker Deployment

#### Single Container
```bash
# Build image
docker build -t ai-waf:latest .

# Run container
docker run -d \
  --name ai-waf \
  -p 8000:8000 \
  -p 8080:8080 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/models:/app/models \
  --env-file .env \
  ai-waf:latest
```

#### Docker Compose (Recommended)
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f waf-core

# Scale WAF instances
docker-compose up -d --scale waf-core=3

# Stop services
docker-compose down
```

### 3. Kubernetes Deployment

#### Prerequisites
```bash
# Install kubectl and helm
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

#### Deploy with Helm
```bash
# Add WAF Helm repository
helm repo add ai-waf https://charts.your-org.com/ai-waf
helm repo update

# Create namespace
kubectl create namespace waf-system

# Install WAF
helm install ai-waf ai-waf/ai-waf \
  --namespace waf-system \
  --values values-production.yaml

# Check deployment
kubectl get pods -n waf-system
kubectl get services -n waf-system
```

#### Manual Kubernetes Deployment
```bash
# Apply configurations
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/postgresql.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/waf-deployment.yaml
kubectl apply -f k8s/waf-service.yaml
kubectl apply -f k8s/ingress.yaml

# Verify deployment
kubectl get all -n waf-system
```

### 4. Cloud Provider Deployments

#### AWS Deployment

##### Using ECS Fargate
```bash
# Create ECS cluster
aws ecs create-cluster --cluster-name ai-waf-cluster

# Create task definition
aws ecs register-task-definition --cli-input-json file://aws/task-definition.json

# Create service
aws ecs create-service \
  --cluster ai-waf-cluster \
  --service-name ai-waf-service \
  --task-definition ai-waf:1 \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-12345],securityGroups=[sg-12345],assignPublicIp=ENABLED}"
```

##### Using EKS
```bash
# Create EKS cluster
eksctl create cluster --name ai-waf-cluster --region us-west-2 --nodes 3

# Configure kubectl
aws eks update-kubeconfig --region us-west-2 --name ai-waf-cluster

# Deploy using Helm
helm install ai-waf ./helm-chart --namespace waf-system --create-namespace
```

##### Using EC2 with Auto Scaling
```bash
# Deploy using Terraform
cd deployment/aws
terraform init
terraform plan -var-file="production.tfvars"
terraform apply -var-file="production.tfvars"
```

#### Azure Deployment

##### Using Container Instances
```bash
# Create resource group
az group create --name waf-rg --location eastus

# Deploy container group
az container create \
  --resource-group waf-rg \
  --name ai-waf \
  --image your-registry.azurecr.io/ai-waf:latest \
  --cpu 4 \
  --memory 8 \
  --ports 8000 8080 \
  --environment-variables REDIS_URL=redis://redis:6379
```

##### Using AKS
```bash
# Create AKS cluster
az aks create \
  --resource-group waf-rg \
  --name ai-waf-cluster \
  --node-count 3 \
  --node-vm-size Standard_D4s_v3 \
  --enable-addons monitoring

# Get credentials
az aks get-credentials --resource-group waf-rg --name ai-waf-cluster

# Deploy application
kubectl apply -f k8s/
```

#### GCP Deployment

##### Using Cloud Run
```bash
# Build and push image
gcloud builds submit --tag gcr.io/PROJECT_ID/ai-waf

# Deploy to Cloud Run
gcloud run deploy ai-waf \
  --image gcr.io/PROJECT_ID/ai-waf \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 4Gi \
  --cpu 2
```

##### Using GKE
```bash
# Create GKE cluster
gcloud container clusters create ai-waf-cluster \
  --zone us-central1-a \
  --num-nodes 3 \
  --machine-type n1-standard-4

# Get credentials
gcloud container clusters get-credentials ai-waf-cluster --zone us-central1-a

# Deploy application
kubectl apply -f k8s/
```

## Production Configuration

### High Availability Setup

#### Load Balancer Configuration
```nginx
# /etc/nginx/sites-available/waf-lb
upstream waf_backend {
    least_conn;
    server waf1.internal:8000 max_fails=3 fail_timeout=30s;
    server waf2.internal:8000 max_fails=3 fail_timeout=30s;
    server waf3.internal:8000 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    listen 443 ssl http2;
    server_name waf.yourdomain.com;

    ssl_certificate /etc/ssl/certs/waf.crt;
    ssl_certificate_key /etc/ssl/private/waf.key;

    location / {
        proxy_pass http://waf_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Health check
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 30s;
    }
    
    location /health {
        access_log off;
        proxy_pass http://waf_backend/health;
    }
}
```

#### Database Clustering

##### PostgreSQL HA with Patroni
```yaml
# patroni.yml
scope: waf-cluster
namespace: /waf/
name: waf-db-1

restapi:
  listen: 0.0.0.0:8008
  connect_address: waf-db-1:8008

etcd:
  hosts: etcd1:2379,etcd2:2379,etcd3:2379

bootstrap:
  dcs:
    ttl: 30
    loop_wait: 10
    retry_timeout: 60
    maximum_lag_on_failover: 1048576
    postgresql:
      use_pg_rewind: true
      parameters:
        max_connections: 200
        shared_preload_libraries: pg_stat_statements
        
postgresql:
  listen: 0.0.0.0:5432
  connect_address: waf-db-1:5432
  data_dir: /var/lib/postgresql/data
  bin_dir: /usr/lib/postgresql/14/bin
  authentication:
    replication:
      username: replicator
      password: repl_password
    superuser:
      username: postgres
      password: postgres_password
```

##### Redis Cluster
```bash
# Create Redis cluster
redis-cli --cluster create \
  redis1:6379 redis2:6379 redis3:6379 \
  redis4:6379 redis5:6379 redis6:6379 \
  --cluster-replicas 1
```

### Security Hardening

#### SSL/TLS Configuration
```bash
# Generate SSL certificates
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout /etc/ssl/private/waf.key \
  -out /etc/ssl/certs/waf.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=waf.yourdomain.com"

# Set proper permissions
chmod 600 /etc/ssl/private/waf.key
chmod 644 /etc/ssl/certs/waf.crt
```

#### Firewall Rules
```bash
# UFW configuration
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow from 10.0.0.0/8 to any port 8000  # Internal API access
ufw allow from 10.0.0.0/8 to any port 9090  # Metrics access
ufw enable
```

#### SELinux/AppArmor
```bash
# SELinux configuration
setsebool -P httpd_can_network_connect 1
semanage port -a -t http_port_t -p tcp 8000
semanage port -a -t http_port_t -p tcp 8080

# AppArmor profile
cat > /etc/apparmor.d/waf-profile << EOF
#include <tunables/global>

/usr/bin/python3 {
  #include <abstractions/base>
  #include <abstractions/python>
  
  /app/** r,
  /app/logs/** rw,
  /app/models/** rw,
  /tmp/** rw,
  
  network inet stream,
  network inet dgram,
  
  capability net_raw,
  capability net_admin,
}
EOF

apparmor_parser -r /etc/apparmor.d/waf-profile
```

### Monitoring Setup

#### Prometheus Configuration
```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "waf_alerts.yml"

scrape_configs:
  - job_name: 'waf-instances'
    static_configs:
      - targets: ['waf1:9090', 'waf2:9090', 'waf3:9090']
    scrape_interval: 5s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node1:9100', 'node2:9100', 'node3:9100']

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['redis-exporter:9121']

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']
```

#### Grafana Dashboard Import
```bash
# Import WAF dashboard
curl -X POST \
  http://admin:admin@grafana:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @monitoring/grafana/waf-dashboard.json
```

### Backup and Recovery

#### Database Backup
```bash
#!/bin/bash
# backup-db.sh

BACKUP_DIR="/backups/postgresql"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="waf_db"

# Create backup
pg_dump -h localhost -U waf_user -d $DB_NAME | gzip > $BACKUP_DIR/waf_db_$DATE.sql.gz

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "waf_db_*.sql.gz" -mtime +30 -delete

# Upload to S3 (optional)
aws s3 cp $BACKUP_DIR/waf_db_$DATE.sql.gz s3://waf-backups/postgresql/
```

#### Configuration Backup
```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/backups/config"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup configuration files
tar -czf $BACKUP_DIR/waf_config_$DATE.tar.gz \
  /app/config/ \
  /app/.env \
  /etc/nginx/sites-available/waf-lb \
  /etc/ssl/certs/waf.crt

# Upload to S3
aws s3 cp $BACKUP_DIR/waf_config_$DATE.tar.gz s3://waf-backups/config/
```

## Performance Tuning

### System Optimization
```bash
# Kernel parameters
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 65536 134217728' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 4096 65536 134217728' >> /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf
sysctl -p

# File descriptor limits
echo '* soft nofile 65536' >> /etc/security/limits.conf
echo '* hard nofile 65536' >> /etc/security/limits.conf
```

### Application Tuning
```bash
# Environment variables for production
export PROCESSING_THREADS=8
export PACKET_BUFFER_SIZE=2000000
export MAX_CONCURRENT_CONNECTIONS=20000
export ENABLE_GPU=true
export BATCH_SIZE=64
```

### Database Optimization
```sql
-- PostgreSQL optimization
ALTER SYSTEM SET shared_buffers = '8GB';
ALTER SYSTEM SET effective_cache_size = '24GB';
ALTER SYSTEM SET maintenance_work_mem = '2GB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
SELECT pg_reload_conf();
```

## Troubleshooting

### Common Issues

#### High Memory Usage
```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head -10

# Adjust application settings
export PACKET_BUFFER_SIZE=500000
export PROCESSING_THREADS=4
```

#### Database Connection Issues
```bash
# Check PostgreSQL status
systemctl status postgresql
pg_isready -h localhost -p 5432

# Check connections
sudo -u postgres psql -c "SELECT count(*) FROM pg_stat_activity;"
```

#### Network Performance
```bash
# Check network interface
ethtool eth0
iftop -i eth0

# Monitor packet drops
netstat -i
cat /proc/net/dev
```

### Log Analysis
```bash
# WAF application logs
tail -f logs/waf.log | jq .

# System logs
journalctl -u waf -f

# Performance analysis
grep "processing_time" logs/waf.log | awk '{print $NF}' | sort -n
```

## Maintenance

### Regular Maintenance Tasks
```bash
#!/bin/bash
# maintenance.sh

# Update threat intelligence feeds
curl -X POST http://localhost:8000/api/v1/threat-intel/update

# Cleanup old logs
find logs/ -name "*.log" -mtime +7 -delete

# Database maintenance
sudo -u postgres psql waf_db -c "VACUUM ANALYZE;"

# Model retraining (weekly)
if [ $(date +%u) -eq 1 ]; then
    curl -X POST http://localhost:8000/api/v1/ml/models/train
fi
```

### Update Procedures
```bash
# Application update
git pull origin main
pip install -r requirements.txt --upgrade
systemctl restart waf

# Database migrations
alembic upgrade head

# Configuration updates
systemctl reload nginx
```

This deployment guide provides comprehensive instructions for deploying the AI-Driven WAF in various environments, from development to enterprise production systems.