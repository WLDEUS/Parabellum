# Parabellum : points d'entrée de build. Cible principale : macOS 14+ sur Apple Silicon (arm64).
# `make test`, `make lint` et `make dev-daemon` fonctionnent aussi sous Linux (code macOS remplacé par des stubs).
# `make` sans argument affiche l'aide.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help
MAKEFLAGS += --no-print-directory

# The checkout path may contain spaces (".../Repos Perso/Parabellum"): make's path functions ($(dir),
# $(abspath)…) split words on spaces, so use the directory make runs in. Run `make` from the repo root
# (or `make -C <repo>`); every recipe quotes "$(ROOT_DIR)".
ROOT_DIR := $(CURDIR)
ifneq ($(shell test -f "$(ROOT_DIR)/Cargo.toml" && test -d "$(ROOT_DIR)/scripts" && echo ok),ok)
$(error lancez make depuis la racine du dépôt Parabellum (ou make -C <chemin du dépôt>))
endif
UNAME_S := $(shell uname -s)
TARGET := aarch64-apple-darwin
CARGO ?= cargo
SWIFT ?= swift

# Version : [workspace.package] version de Cargo.toml ; build : nombre de commits git (ou date UTC).
VERSION := $(shell "$(ROOT_DIR)/scripts/version.sh" 2>/dev/null || echo 0.0.0)
BUILD_NUMBER := $(shell "$(ROOT_DIR)/scripts/version.sh" --build 2>/dev/null || echo 0)

DIST := $(ROOT_DIR)/dist
APP := $(DIST)/Parabellum.app
PKG := $(DIST)/Parabellum-$(VERSION).pkg
DEV_ROOT := $(ROOT_DIR)/.dev-root
DEV_SOCKET := $(DEV_ROOT)/run/parabellum.sock

.PHONY: help version dev-check prereqs build build-rust build-swift app pkg install uninstall \
	test lint fmt keys codesign-cert dev-daemon dev-app dev-cli clean distclean

help: ## Affiche cette aide
	@printf 'Parabellum %s (build %s)\n\nUsage : make <cible> [VARIABLE=valeur]\n\n' "$(VERSION)" "$(BUILD_NUMBER)"
	@awk 'BEGIN { FS = ":.*## " } /^[a-zA-Z_-]+:.*## / { printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf '\nVariables : PURGE=1 (uninstall), ARGS="..." (dev-cli), CARGO=, SWIFT=\n'
	@printf 'Premier build : make dev-check -> make keys -> make codesign-cert -> make pkg -> make install\n'
	@printf 'Puis : Accès complet au disque pour parabellumd (voir docs/INSTALL.md)\n'

version: ## Affiche la version et le numéro de build
	@echo "$(VERSION) ($(BUILD_NUMBER))"

dev-check: ## Vérifie les outils du Mac de dev (macOS, arm64, Xcode, Rust, Swift…)
	@"$(ROOT_DIR)/scripts/dev-check.sh"

prereqs:
	@[[ "$(UNAME_S)" == "Darwin" ]] || { echo "erreur : cible macOS uniquement (ici : make test, lint, dev-daemon)" >&2; exit 1; }
	@[[ "$$(uname -m)" == "arm64" ]] || { echo "erreur : Mac Apple Silicon (arm64) requis, terminal hors Rosetta" >&2; exit 1; }
	@xcode-select -p >/dev/null 2>&1 || { echo "erreur : outils Xcode absents : xcode-select --install" >&2; exit 1; }
	@command -v rustup >/dev/null 2>&1 || { echo "erreur : rustup absent : https://rustup.rs" >&2; exit 1; }
	@command -v $(SWIFT) >/dev/null 2>&1 || { echo "erreur : swift absent : xcode-select --install" >&2; exit 1; }
	@rustup target list --installed | grep -qx '$(TARGET)' || { echo "==> rustup target add $(TARGET)"; rustup target add $(TARGET); }

build: build-rust build-swift ## Compile tout : daemon + CLI (Rust) et app (Swift), release arm64

build-rust: prereqs ## Compile parabellumd et parabellum (release, aarch64-apple-darwin)
	cd "$(ROOT_DIR)" && MACOSX_DEPLOYMENT_TARGET=14.0 $(CARGO) build --locked --release --target $(TARGET) -p pb-daemon -p pb-cli

build-swift: prereqs ## Compile l'app SwiftUI (release, arm64)
	cd "$(ROOT_DIR)/app" && $(SWIFT) build -c release --arch arm64

app: build-swift ## Assemble et signe (ad hoc) dist/Parabellum.app
	"$(ROOT_DIR)/scripts/build-app.sh" --skip-build

pkg: prereqs ## Construit dist/Parabellum-<version>.pkg (recompile tout, signe, empaquette)
	"$(ROOT_DIR)/scripts/build-pkg.sh"

install: ## Installe dist/Parabellum-<version>.pkg sur ce Mac (sudo)
	@[[ -f "$(PKG)" ]] || { echo "erreur : $(PKG) absent : lancez make pkg" >&2; exit 1; }
	sudo /usr/sbin/installer -pkg "$(PKG)" -target /
	@echo "Étape suivante : Accès complet au disque pour parabellumd (docs/INSTALL.md, section 5)"

uninstall: ## Désinstalle (garde quarantaine, historique, config) ; PURGE=1 efface aussi les données
	sudo /bin/bash "$(ROOT_DIR)/scripts/uninstall.sh" $(if $(filter 1,$(PURGE)),--purge)

test: ## Tests Rust (workspace) + tests Swift (macOS)
	cd "$(ROOT_DIR)" && $(CARGO) test --workspace
	@if [[ "$(UNAME_S)" == "Darwin" && -f "$(ROOT_DIR)/app/Package.swift" ]]; then \
	echo "==> swift test"; cd "$(ROOT_DIR)/app" && $(SWIFT) test; \
	else echo "(swift test ignoré : macOS et app/Package.swift requis)"; fi

lint: ## cargo fmt --check, clippy -D warnings, shellcheck des scripts
	cd "$(ROOT_DIR)" && $(CARGO) fmt --all -- --check
	cd "$(ROOT_DIR)" && $(CARGO) clippy --workspace --all-targets -- -D warnings
	@if command -v shellcheck >/dev/null 2>&1; then \
	echo "==> shellcheck"; cd "$(ROOT_DIR)" && shellcheck -x scripts/*.sh scripts/lib/*.sh installer/scripts/preinstall installer/scripts/postinstall; \
	else echo "(shellcheck absent : ignoré, brew install shellcheck)"; fi

fmt: ## Formate le code Rust
	cd "$(ROOT_DIR)" && $(CARGO) fmt --all

codesign-cert: ## Crée le certificat de signature stable (accès complet au disque conservé) + secrets CI
	"$(ROOT_DIR)/scripts/setup-codesign-cert.sh"

keys: ## Crée la paire de clés minisign de la base de menaces (scripts/setup-signing-keys.sh)
	@[[ -f "$(ROOT_DIR)/scripts/setup-signing-keys.sh" ]] || { echo "erreur : scripts/setup-signing-keys.sh absent" >&2; exit 1; }
	/bin/bash "$(ROOT_DIR)/scripts/setup-signing-keys.sh"

dev-daemon: ## Lance le daemon en dev, sans root, tout sous .dev-root/
	mkdir -p "$(DEV_ROOT)"
	cd "$(ROOT_DIR)" && PARABELLUM_ROOT="$(DEV_ROOT)" RUST_LOG="$${RUST_LOG:-debug}" $(CARGO) run -p pb-daemon

dev-app: ## Lance l'app contre le daemon de dev (.dev-root/run/parabellum.sock)
	@[[ "$(UNAME_S)" == "Darwin" ]] || { echo "erreur : macOS uniquement" >&2; exit 1; }
	cd "$(ROOT_DIR)/app" && PARABELLUM_SOCKET="$(DEV_SOCKET)" $(SWIFT) run Parabellum

dev-cli: ## Lance la CLI contre le daemon de dev : make dev-cli ARGS="status"
	cd "$(ROOT_DIR)" && PARABELLUM_SOCKET="$(DEV_SOCKET)" $(CARGO) run -q -p pb-cli -- $(ARGS)

clean: ## Supprime dist/, .dev-root/ et le build Swift (garde target/ de cargo)
	rm -rf "$(DIST)" "$(DEV_ROOT)" "$(ROOT_DIR)/app/.build"

distclean: clean ## clean + cargo clean
	cd "$(ROOT_DIR)" && $(CARGO) clean
