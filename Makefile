PLUGIN_NAME := vault-plugin-secrets-pingfederate
BUILD_DIR   := .local/builds
PLUGIN_DIR  := .local/vault/plugins
PLATFORMS   := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

export VAULT_ADDR  := http://127.0.0.1:8200
export VAULT_TOKEN := root

.PHONY: build clean dev enable

build:
	@mkdir -p $(BUILD_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		echo "Building $(PLUGIN_NAME)-$${os}-$${arch}"; \
		CGO_ENABLED=0 GOOS=$${os} GOARCH=$${arch} \
			go build -o $(BUILD_DIR)/$(PLUGIN_NAME)-$${os}-$${arch} ./cmd/$(PLUGIN_NAME); \
	done

dev: build
	@mkdir -p $(PLUGIN_DIR)
	@cp $(BUILD_DIR)/$(PLUGIN_NAME)-$(shell go env GOOS)-$(shell go env GOARCH) $(PLUGIN_DIR)/$(PLUGIN_NAME)
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=$(PLUGIN_DIR)

clean:
	rm -rf $(BUILD_DIR) $(PLUGIN_DIR)

enable:
	vault secrets enable -path=pingfederate $(PLUGIN_NAME)
