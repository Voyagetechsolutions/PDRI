# PDRI - Predictive Data Risk Infrastructure

> A self-learning intelligence system that understands how data risk evolves in a world where AI, cloud, and human behavior constantly reshape exposure.

## 🏗️ Architecture

```
Aegis AI (Eyes) → PDRI (Brain) → Platform UI (Dashboard)
```

- **PDRI** - Risk intelligence engine with graph-based modeling
- **Aegis AI** - AI usage detection and exposure sensor
- **Platform** - Unified security dashboard and operations center

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Neo4j Desktop (optional, for graph visualization)

### Setup

```bash
# Clone and setup
cd PDRI

# Create virtual environment
python -m venv venv
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Copy environment template
copy .env.example .env  # Windows
cp .env.example .env    # Linux/Mac

# Start infrastructure
docker-compose up -d

# Verify services
docker-compose ps

# Run API server
uvicorn pdri.api.main:app --reload
```

### Access Points
- **PDRI API**: http://localhost:8000/docs
- **Neo4j Browser**: http://localhost:7474
- **Kafka**: localhost:9092

## 📁 Project Structure

```
PDRI/
├── shared/schemas/        # Platform-wide event schemas
├── pdri/
│   ├── api/              # FastAPI REST API
│   ├── graph/            # Neo4j graph engine
│   ├── scoring/          # Risk scoring engine
│   ├── ingestion/        # Kafka event ingestion
│   └── simulation/       # Risk simulation
├── aegis_ai/             # AI detection sensor integration
└── tests/                # Test suite
```

## 📚 Documentation

- [Implementation Plan](./docs/implementation_plan.md)
- [API Reference](./docs/api.md)
- [Event Schema](./docs/events.md)
- [Graph Model](./docs/graph.md)

## 🔧 Configuration

See `.env.example` for all configuration options.

## 📄 License

Proprietary - All rights reserved.
