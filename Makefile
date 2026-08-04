# Makefile for Reverse Engineering Lab
# Common development and deployment tasks

.PHONY: help install test run example docker-build docker-run clean lint

# Variables
PYTHON = python3
PIP = pip
PROJECT_DIR = $(shell pwd)

# Help target
help:
	@echo "Reverse Engineering Lab - Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make help          Show this help message"
	@echo "  make install       Install Python dependencies"
	@echo "  make test          Run tests"
	@echo "  make example       Run the example usage demonstration"
	@echo "  make run           Start the interactive system"
	@echo "  make docker-build  Build Docker image"
	@echo "  make docker-run    Run Docker container"
	@echo "  make clean         Clean temporary files"
	@echo "  make lint          Run code linter"

# Install dependencies
install:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "Dependencies installed"

# Run tests
test:
	$(PYTHON) -m pytest tests/ -v

# Run example usage
example:
	$(PYTHON) example_usage.py

# Run interactive system (would need actual firmware/files to analyze)
run:
	$(PYTHON) -c "from startup import main; import asyncio; asyncio.run(main())"

# Build Docker image
docker-build:
	docker build -t reverse-engineering-lab:latest .

# Run Docker container
docker-run:
	docker run --rm -it \
		-v $(PWD)/data:/app/data \
		-v $(PWD)/logs:/app/logs \
		-v $(PWD)/config:/app/config \
		reverse-engineering-lab:latest

# Clean temporary files
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.log" -delete
	rm -rf .pytest_cache .coverage htmlcov
	@echo "Cleaned temporary files"

# Lint code (requires flake8 or pylint)
lint:
	@echo "Linting not configured - install flake8 or pylint to use this target"
	@echo "Example: pip install flake8 && flake8 ."

# Development server for docs (if using mkdocs)
docs-serve:
	@echo "Docs serving not configured - install mkdocs to use this target"

# Format code (if using black)
format:
	@echo "Code formatting not configured - install black to use this target"
	@echo "Example: pip install black && black ."

# Default target
default: help