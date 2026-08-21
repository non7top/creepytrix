# Disposable-container entry points. Everything runs in a throwaway,
# non-root container built from the committed Dockerfile + requirements.
# Nothing is installed on the host.

DOCKER_UID := $(shell id -u)
DOCKER_GID := $(shell id -g)
export DOCKER_UID
export DOCKER_GID

COMPOSE := docker compose
SVC := creepytrix

.PHONY: help build run local test lint shell stop destroy

help:
	@echo "Targets:"
	@echo "  build            Build the image"
	@echo "  run ARGS=...     Run the scanner (e.g. make run ARGS='https://site -m rce')"
	@echo "  local ROOT=/path Local host scan of a Bitrix root (mounted at /target)"
	@echo "  test             Run the test suite (pytest)"
	@echo "  lint             Lint with ruff"
	@echo "  shell            Open a shell in the container"
	@echo "  stop             Tear down compose state"
	@echo "  destroy          Tear down and remove the image"

build:
	$(COMPOSE) build

# make run ARGS="https://example.com -m rce -o out.json"
run:
	$(COMPOSE) run --rm $(SVC) $(ARGS)

# make local ROOT=/home/bitrix/www        (ROOT is bind-mounted read-only at /target)
# make local                              (auto-detect inside the container)
local:
	$(COMPOSE) run --rm $(if $(ROOT),-v $(ROOT):/target:ro) $(SVC) \
		--local $(if $(ROOT),--web-root /target) $(ARGS)

test:
	$(COMPOSE) run --rm --entrypoint python $(SVC) -m pytest -q tests

lint:
	$(COMPOSE) run --rm --entrypoint ruff $(SVC) check .

shell:
	$(COMPOSE) run --rm --entrypoint bash $(SVC)

stop:
	$(COMPOSE) down --remove-orphans

destroy:
	$(COMPOSE) down --rmi local --volumes --remove-orphans
