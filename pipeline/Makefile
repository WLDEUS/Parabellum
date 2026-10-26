# Local helpers for the threat-DB pipeline (run from the repository root: make -C pipeline <target>).
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
PY ?= python3
OUT ?= $(ROOT)/dist/db
CACHE ?= $(ROOT)/.cache/corpus
VENV ?= $(ROOT)/.venv-pipeline

.PHONY: help venv test lint build-offline build corpus-local
help:
	@echo "make -C pipeline venv          create $(VENV) with the pinned dependencies"
	@echo "make -C pipeline test lint     pytest + ruff for pipeline/ and ml/"
	@echo "make -C pipeline build-offline bundle from local data + GitHub lists, no abuse.ch"
	@echo "make -C pipeline build         full bundle (needs ABUSECH_AUTH_KEY), unsigned"
	@echo "make -C pipeline corpus-local  same + detection measurement on today's macOS samples (Linux box)"

venv:
	$(PY) -m venv $(VENV)
	$(VENV)/bin/pip install -r $(ROOT)/pipeline/requirements-dev.txt -r $(ROOT)/ml/requirements.txt

test:
	cd $(ROOT) && $(PY) -m pytest -q pipeline/tests ml/tests

lint:
	cd $(ROOT) && $(PY) -m ruff check pipeline ml && $(PY) -m ruff format --check pipeline ml

build-offline:
	cd $(ROOT) && $(PY) -m pipeline.build --out $(OUT) --corpus-cache $(CACHE) --offline

build:
	cd $(ROOT) && $(PY) -m pipeline.build --out $(OUT) --corpus-cache $(CACHE)

# Detection measurement on a machine you control (Linux, never macOS: samples are Mach-O/DMG). Samples
# are decrypted in memory, written 0600 to a private temp dir only for scanning, then deleted.
corpus-local:
	@test -n "$$ABUSECH_AUTH_KEY" || { echo "ABUSECH_AUTH_KEY is not set" >&2; exit 1; }
	@test "$$(uname -s)" = "Linux" || { echo "run this on Linux, not on the Mac you protect" >&2; exit 1; }
	cd $(ROOT) && cargo build --release -p pb-ml --bin pb-features
	cd $(ROOT) && MALWARE_CORPUS=1 $(PY) -m pipeline.build --out $(OUT) --corpus-cache $(CACHE) \
		--pb-features $(ROOT)/target/release/pb-features
	@$(PY) -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])).get("detection"), indent=2))' $(OUT)/report.json
