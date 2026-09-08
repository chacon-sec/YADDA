# Builds the node_agent Go plugin (.so) for the AdaptixC2 teamserver.
#
# Go plugins must be built with the EXACT toolchain + experiments + shared
# module versions as the host server binary — so we build inside the same
# docker image AdaptixC2's own extender builds use. That image must exist
# first (one-time, from your AdaptixC2 checkout):
#
#   cd /path/to/AdaptixC2
#   docker compose --profile build-server-ext build server-ext-builder
#   # -> adaptixc2-server-ext-builder:latest
#
# And the JS payload that gets baked into generated payloads comes from this
# repo's build output (npm run build -> dist/adaptix.payload.obf.js), so run
# that first whenever src/ changes.
#
#   make build                               # -> dist/ (agent_node.so, config.yaml,
#                                           #     ax_config.axs, payload.node.js)
#   make deploy ADAPTIX_DIR=/path/to/AdaptixC2
#                                           # build + install into the running
#                                           # teamserver container + add the
#                                           # profile.yaml extenders entry +
#                                           # restart it
#   make deploy CONTAINER=my-server ADAPTIX_DIR=...
#                                           # non-default container name
IMAGE ?= adaptixc2-server-ext-builder:latest
CONTAINER ?= adaptix-server-runtime
ADAPTIX_DIR ?=

all: build

build:
	@test -f ../dist/adaptix.payload.obf.js || { \
	  echo "[!] ../dist/adaptix.payload.obf.js missing — run 'npm run build' in the repo root first"; exit 1; }
	@docker image inspect $(IMAGE) >/dev/null 2>&1 || { \
	  echo "[!] builder image $(IMAGE) not found."; \
	  echo "    Build it once from your AdaptixC2 checkout:"; \
	  echo "      cd <AdaptixC2> && docker compose --profile build-server-ext build server-ext-builder"; \
	  exit 1; }
	@ mkdir -p dist
	@ docker run --rm -v $(CURDIR):/build -w /build \
	    -e GOFLAGS=-mod=mod -e GOCACHE=/tmp/gocache \
	    -e GOEXPERIMENT=jsonv2,greenteagc \
	    $(IMAGE) bash -c "go build -buildmode=plugin -ldflags='-s -w' -o dist/agent_node.so pl_main.go"
	@ cp config.yaml ax_config.axs dist/
	@ cp ../dist/adaptix.payload.obf.js dist/payload.node.js
	@ echo "[+] built dist/: agent_node.so config.yaml ax_config.axs payload.node.js"

# Deploy target = install into the HOST directory the teamserver container
# bind-mounts at /app/extenders/node_agent (see docker-compose.override.yml:
# ./AdaptixServer/server-dist/node_agent_ext:/app/extenders/node_agent:ro).
# Copying to the host dir (not docker cp) works with the read-only mount AND
# survives container recreation. For a non-docker server, point EXTDIR at
# wherever that server's extenders/ lives.
EXTDIR ?= $(ADAPTIX_DIR)/AdaptixServer/server-dist/node_agent_ext

deploy: build
	@test -n "$(ADAPTIX_DIR)" || { \
	  echo "[!] ADAPTIX_DIR not set — point it at your AdaptixC2 checkout:"; \
	  echo "      make deploy ADAPTIX_DIR=/path/to/AdaptixC2"; exit 1; }
	@ mkdir -p $(EXTDIR)
	@ cp dist/agent_node.so   $(EXTDIR)/
	@ cp dist/config.yaml     $(EXTDIR)/
	@ cp dist/ax_config.axs   $(EXTDIR)/
	@ cp dist/payload.node.js $(EXTDIR)/
	@grep -q node_agent $(ADAPTIX_DIR)/AdaptixServer/server-dist/profile.yaml || \
	  sed -i '' 's#- "extenders/gopher_agent/config.yaml"#- "extenders/gopher_agent/config.yaml"\n    - "extenders/node_agent/config.yaml"#' \
	    $(ADAPTIX_DIR)/AdaptixServer/server-dist/profile.yaml && echo "[+] profile.yaml: extenders entry added"
	@ docker restart $(CONTAINER)
	@ echo "[+] deployed to $(EXTDIR) + teamserver restarting"
	@ echo "[i] requires the compose bind-mount of that dir at /app/extenders/node_agent"
	@ echo "    (docker-compose.override.yml in the AdaptixC2 checkout):"
	@ echo "      - ./AdaptixServer/server-dist/node_agent_ext:/app/extenders/node_agent:ro"

clean:
	@ rm -rf dist

.PHONY: all build deploy clean
