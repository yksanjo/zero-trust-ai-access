.PHONY: help install dev-install test lint format type-check clean docker-build docker-run docker-compose-up docker-compose-down helm-install helm-uninstall

# Default target
help:
	@echo "Available targets:"
	@echo "  install          - Install production dependencies"
	@echo "  dev-install      - Install development dependencies"
	@echo "  test             - Run tests"
	@echo "  lint             - Run linting (ruff)"
	@echo "  format           - Format code (black)"
	@echo "  type-check       - Run type checking (mypy)"
	@echo "  clean            - Clean build artifacts"
	@echo "  docker-build     - Build Docker image"
	@echo "  docker-run       - Run Docker container"
	@echo "  docker-compose-up   - Start with docker-compose"
	@echo "  docker-compose-down - Stop docker-compose services"
	@echo "  helm-install     - Install Helm chart"
	@echo "  helm-uninstall   - Uninstall Helm chart"

# Installation
install:
	pip install -e .

dev-install:
	pip install -e ".[dev]"
	python -m spacy download en_core_web_lg || true

# Testing
test:
	pytest tests/ -v --cov=app --cov-report=term-missing

test-coverage:
	pytest tests/ -v --cov=app --cov-report=html --cov-report=term

# Code quality
lint:
	ruff check app/ tests/

format:
	black app/ tests/
	isort app/ tests/

format-check:
	black --check app/ tests/

fix:
	ruff check app/ tests/ --fix

type-check:
	mypy app/

# Cleaning
clean:
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# Docker
docker-build:
	docker build -t zero-trust-ai-access:latest .

docker-run: docker-build
	docker run -p 8000:8000 --env-file .env zero-trust-ai-access:latest

docker-compose-up:
	docker-compose up -d

docker-compose-down:
	docker-compose down

docker-compose-logs:
	docker-compose logs -f gateway

docker-compose-build:
	docker-compose up -d --build

# Helm
helm-install:
	helm install zero-trust-ai ./helm \
		--namespace zero-trust-ai \
		--create-namespace \
		--wait

helm-upgrade:
	helm upgrade zero-trust-ai ./helm \
		--namespace zero-trust-ai \
		--wait

helm-uninstall:
	helm uninstall zero-trust-ai --namespace zero-trust-ai

helm-template:
	helm template zero-trust-ai ./helm \
		--namespace zero-trust-ai

# Development server
dev:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

run:
	python -m app.main

# Database
migrate:
	@echo "Running database migrations..."
	@echo "Note: Migrations run automatically on startup"

db-shell:
	@echo "Connecting to PostgreSQL..."
	docker-compose exec postgres psql -U postgres -d zerotrust_ai

redis-cli:
	docker-compose exec redis redis-cli

# Documentation
docs:
	@echo "API documentation available at:"
	@echo "  Swagger UI: http://localhost:8000/docs"
	@echo "  ReDoc: http://localhost:8000/redoc"

# All checks
check: format-check lint type-check test
	@echo "All checks passed!"

# CI/CD
ci: install lint type-check test
	@echo "CI pipeline completed"
