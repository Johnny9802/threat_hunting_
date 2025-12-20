#!/bin/bash
# Quick start script for Docker deployment

set -e

echo "🐳 Threat Hunting Playbook - Docker Deployment"
echo "=============================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if .env exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from .env.example..."
    cp .env.example .env
    echo "✅ Created .env file. Please edit it with your API keys if needed."
    echo ""
fi

# Parse command line arguments
COMMAND=${1:-up}

case $COMMAND in
    up)
        echo "🚀 Starting all services..."
        docker-compose up -d
        echo ""
        echo "✅ Services started!"
        echo ""
        echo "📊 Status:"
        docker-compose ps
        echo ""
        echo "🌐 Access points:"
        echo "  - API:        http://localhost:8000"
        echo "  - API Docs:   http://localhost:8000/docs"
        echo "  - Health:     http://localhost:8000/health"
        echo ""
        echo "📝 View logs: docker-compose logs -f"
        ;;

    down)
        echo "🛑 Stopping all services..."
        docker-compose down
        echo "✅ Services stopped"
        ;;

    restart)
        echo "🔄 Restarting services..."
        docker-compose restart
        echo "✅ Services restarted"
        ;;

    logs)
        echo "📋 Viewing logs (Ctrl+C to exit)..."
        docker-compose logs -f
        ;;

    build)
        echo "🔨 Building Docker images..."
        docker-compose build
        echo "✅ Build complete"
        ;;

    status)
        echo "📊 Service status:"
        docker-compose ps
        ;;

    clean)
        echo "🧹 Cleaning up (WARNING: This will delete volumes)..."
        read -p "Are you sure? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            docker-compose down -v
            echo "✅ Cleanup complete"
        else
            echo "❌ Cancelled"
        fi
        ;;

    test)
        echo "🧪 Testing API endpoints..."
        echo ""

        # Wait for API to be ready
        echo "⏳ Waiting for API to be ready..."
        timeout=30
        while [ $timeout -gt 0 ]; do
            if curl -s http://localhost:8000/health > /dev/null 2>&1; then
                break
            fi
            sleep 1
            ((timeout--))
        done

        if [ $timeout -eq 0 ]; then
            echo "❌ API failed to start"
            exit 1
        fi

        echo "✅ API is ready!"
        echo ""

        # Test endpoints
        echo "1️⃣  Testing health endpoint..."
        curl -s http://localhost:8000/health | python3 -m json.tool
        echo ""

        echo "2️⃣  Testing playbooks list..."
        curl -s http://localhost:8000/api/playbooks | python3 -m json.tool | head -20
        echo ""

        echo "3️⃣  Testing statistics..."
        curl -s http://localhost:8000/api/stats | python3 -m json.tool
        echo ""

        echo "✅ All tests passed!"
        ;;

    cli)
        echo "💻 Running CLI command: ${@:2}"
        docker-compose --profile cli run --rm cli "${@:2}"
        ;;

    shell)
        SERVICE=${2:-api}
        echo "🐚 Opening shell in $SERVICE container..."
        docker-compose exec $SERVICE /bin/sh
        ;;

    db)
        echo "🗄️  Connecting to database..."
        docker-compose exec postgres psql -U threat_hunter -d threat_hunting
        ;;

    redis)
        echo "📮 Connecting to Redis..."
        docker-compose exec redis redis-cli
        ;;

    backup)
        BACKUP_FILE="backup_$(date +%Y%m%d_%H%M%S).sql"
        echo "💾 Creating database backup: $BACKUP_FILE"
        docker-compose exec postgres pg_dump -U threat_hunter threat_hunting > $BACKUP_FILE
        echo "✅ Backup saved to $BACKUP_FILE"
        ;;

    help|--help|-h)
        echo "Usage: ./docker-run.sh [COMMAND]"
        echo ""
        echo "Commands:"
        echo "  up         Start all services (default)"
        echo "  down       Stop all services"
        echo "  restart    Restart all services"
        echo "  logs       View logs"
        echo "  build      Build Docker images"
        echo "  status     Show service status"
        echo "  clean      Remove all containers and volumes"
        echo "  test       Test API endpoints"
        echo "  cli        Run CLI command (e.g., ./docker-run.sh cli list)"
        echo "  shell      Open shell in container (default: api)"
        echo "  db         Connect to PostgreSQL"
        echo "  redis      Connect to Redis"
        echo "  backup     Backup database"
        echo "  help       Show this help message"
        echo ""
        echo "Examples:"
        echo "  ./docker-run.sh up              # Start services"
        echo "  ./docker-run.sh logs            # View logs"
        echo "  ./docker-run.sh cli list        # Run CLI list command"
        echo "  ./docker-run.sh shell api       # Open shell in API container"
        echo "  ./docker-run.sh test            # Test API"
        ;;

    *)
        echo "❌ Unknown command: $COMMAND"
        echo "Run './docker-run.sh help' for usage information"
        exit 1
        ;;
esac
