.PHONY: help install run test build docker-up docker-down lint clean

help:
	@echo "CyberGuard AI - Enterprise Security & Detection Platform"
	@echo "Available commands:"
	@echo "  make install      - Install backend and frontend dependencies"
	@echo "  make run          - Start backend server locally"
	@echo "  make test         - Run pytest regression suite"
	@echo "  make build        - Build frontend assets"
	@echo "  make docker-up    - Launch full stack with Docker Compose"
	@echo "  make docker-down  - Stop all running containers"

install:
	pip install -e ./backend
	cd frontend && npm install

run:
	python main.py

test:
	pytest ./backend

build:
	cd frontend && npm run build

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

lint:
	flake8 backend
	cd frontend && npm run lint || true

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
