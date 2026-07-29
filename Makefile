.PHONY: bootstrap build check dev lint test typecheck

bootstrap:
	npm install
	uv sync --all-packages

dev:
	npm run dev

lint:
	npm run lint

typecheck:
	npm run typecheck

test:
	npm test

build:
	npm run build

check:
	npm run check
