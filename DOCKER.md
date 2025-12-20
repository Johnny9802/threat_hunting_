# 🐳 Docker Deployment Guide

## Quick Start

### 1. Prerequisites
- Docker 20.10+
- Docker Compose 2.0+

### 2. Configuration

Create `.env` file:
```bash
cp .env.example .env
# Edit .env and add your API keys
```

Required variables:
```bash
# Optional - for AI features
GROQ_API_KEY=your_groq_api_key
OPENAI_API_KEY=your_openai_api_key
AI_PROVIDER=groq

# Database (auto-generated if not set)
DB_USER=threat_hunter
DB_PASSWORD=changeme_in_production
```

### 3. Start Services

```bash
# Build and start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f api
```

### 4. Access the API

- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## Architecture

```
┌─────────────────────────────────────────────┐
│              Nginx (Port 80)                │
│         Reverse Proxy / Load Balancer       │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────┴──────────────────────────┐
│        FastAPI (Port 8000)                  │
│     Threat Hunting Playbook API             │
│  - Search playbooks                         │
│  - Export queries                           │
│  - AI assistant                             │
└──────┬─────────────────┬────────────────────┘
       │                 │
┌──────┴─────┐    ┌──────┴─────┐
│ PostgreSQL │    │   Redis    │
│  Database  │    │   Cache    │
│ (Port 5432)│    │(Port 6379) │
└────────────┘    └────────────┘
```

## Services

### 1. API Server (`api`)
- **Image**: Custom (built from Dockerfile)
- **Port**: 8000
- **Purpose**: REST API endpoints
- **Dependencies**: PostgreSQL, Redis

### 2. PostgreSQL (`postgres`)
- **Image**: postgres:15-alpine
- **Port**: 5432
- **Data**: Persisted in `postgres_data` volume
- **Purpose**: User data, search history, favorites

### 3. Redis (`redis`)
- **Image**: redis:7-alpine
- **Port**: 6379
- **Data**: Persisted in `redis_data` volume
- **Purpose**: Caching API responses

### 4. Nginx (`nginx`)
- **Image**: nginx:alpine
- **Port**: 80, 443
- **Purpose**: Reverse proxy, SSL termination

### 5. CLI Tool (`cli`)
- **Profile**: `cli` (optional)
- **Purpose**: Run CLI commands in Docker

## Usage

### API Examples

```bash
# List all playbooks
curl http://localhost:8000/api/playbooks

# Get specific playbook
curl http://localhost:8000/api/playbooks/PB-T1566-001

# Search playbooks
curl "http://localhost:8000/api/search?tactic=execution"

# Export query
curl http://localhost:8000/api/playbooks/PB-T1566-001/export/splunk

# AI explain (requires API key)
curl -X POST "http://localhost:8000/api/ai/explain?playbook_id=PB-T1566-001"

# Get statistics
curl http://localhost:8000/api/stats
```

### CLI Tool in Docker

```bash
# Start CLI container
docker-compose --profile cli run --rm cli list

# Search playbooks
docker-compose --profile cli run --rm cli search phishing

# Show playbook
docker-compose --profile cli run --rm cli show PB-T1566-001

# Export query
docker-compose --profile cli run --rm cli export PB-T1566-001 --siem splunk
```

## Development

### Build Specific Service

```bash
# Build API only
docker-compose build api

# Build CLI only
docker-compose build cli
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f api
docker-compose logs -f postgres
docker-compose logs -f redis
```

### Access Container Shell

```bash
# API container
docker-compose exec api /bin/sh

# Database
docker-compose exec postgres psql -U threat_hunter -d threat_hunting

# Redis
docker-compose exec redis redis-cli
```

### Database Operations

```bash
# Connect to database
docker-compose exec postgres psql -U threat_hunter -d threat_hunting

# View tables
\dt

# View users
SELECT * FROM users;

# View search history
SELECT * FROM search_history;
```

## Maintenance

### Backup Database

```bash
# Backup
docker-compose exec postgres pg_dump -U threat_hunter threat_hunting > backup.sql

# Restore
docker-compose exec -T postgres psql -U threat_hunter threat_hunting < backup.sql
```

### Update Services

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose down
docker-compose up -d --build
```

### Clean Up

```bash
# Stop services
docker-compose down

# Remove volumes (WARNING: deletes data)
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

## Production Deployment

### Security Checklist

- [ ] Change default database password
- [ ] Enable HTTPS (add SSL certificates)
- [ ] Configure CORS properly
- [ ] Set up firewall rules
- [ ] Enable authentication
- [ ] Use secrets management
- [ ] Enable logging
- [ ] Set up monitoring

### SSL/TLS Setup

1. Add certificates to `docker/ssl/`
2. Update `docker/nginx.conf`:

```nginx
server {
    listen 443 ssl http2;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    # ... rest of config
}
```

### Environment Variables

Production `.env`:
```bash
# Database
DB_USER=secure_user
DB_PASSWORD=strong_random_password

# API
API_SECRET_KEY=your_secret_key_here
ALLOWED_ORIGINS=https://yourdomain.com

# AI (optional)
GROQ_API_KEY=your_production_key
```

### Resource Limits

Add to docker-compose.yml:
```yaml
services:
  api:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 512M
```

## Monitoring

### Health Checks

```bash
# API health
curl http://localhost:8000/health

# All services status
docker-compose ps
```

### Prometheus Metrics (Future)

Add to docker-compose.yml:
```yaml
  prometheus:
    image: prom/prometheus
    volumes:
      - ./docker/prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
```

## Troubleshooting

### API Won't Start

```bash
# Check logs
docker-compose logs api

# Common issues:
# 1. Database not ready - wait for health check
# 2. Port already in use - change port in docker-compose.yml
# 3. Missing environment variables - check .env file
```

### Database Connection Issues

```bash
# Verify database is running
docker-compose ps postgres

# Check database logs
docker-compose logs postgres

# Test connection
docker-compose exec api python -c "from sqlalchemy import create_engine; engine = create_engine('postgresql://threat_hunter:changeme@postgres:5432/threat_hunting'); print(engine.connect())"
```

### Redis Connection Issues

```bash
# Check Redis
docker-compose exec redis redis-cli ping

# Should return: PONG
```

## Performance Tuning

### PostgreSQL

Edit `docker-compose.yml`:
```yaml
postgres:
  command: postgres -c shared_buffers=256MB -c max_connections=200
```

### Redis

```yaml
redis:
  command: redis-server --maxmemory 512mb --maxmemory-policy allkeys-lru
```

## Scaling

### Horizontal Scaling

```bash
# Scale API to 3 instances
docker-compose up -d --scale api=3
```

Update nginx.conf for load balancing:
```nginx
upstream api_backend {
    server api:8000;
    server api:8001;
    server api:8002;
}
```

## Next Steps

- [ ] Set up production environment
- [ ] Configure monitoring (Prometheus/Grafana)
- [ ] Set up log aggregation (ELK stack)
- [ ] Implement authentication
- [ ] Add rate limiting
- [ ] Set up CI/CD for Docker builds
- [ ] Create Kubernetes manifests (v3.0)

---

**Need Help?**
- Issues: https://github.com/Johnny9802/threat_hunting_/issues
- Docs: https://github.com/Johnny9802/threat_hunting_/blob/main/README.md
