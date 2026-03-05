BIN           := $(PWD)/.local/bin
CACHE         := $(PWD)/.local/cache
GOPATH        := $(CACHE)/go
VENV          := $(CACHE)/venv
PATH          := $(BIN):$(PATH)
SHELL         := env PATH=$(PATH) GOPATH=$(GOPATH) /bin/sh
PYTHON        ?= python3

# Versions
go_version           := 1.26.0
golangci_version     := 2.10.1
actionlint_version   := 1.7.11
shellcheck_version   := 0.11.0
yamlfmt_version      := 0.21.0
yamllint_version     := 1.37.1

# Operating System and Architecture
os ?= $(shell uname|tr A-Z a-z)

ifeq ($(shell uname -m),x86_64)
  arch   ?= amd64
  arch_alt ?= x86_64
endif
ifeq ($(shell uname -m),arm64)
  arch     ?= arm64
  arch_alt ?= aarch64
endif
ifeq ($(shell uname -m),aarch64)
  arch     ?= arm64
  arch_alt ?= aarch64
endif

.PHONY: all
all: lint test build

.PHONY: tools
tools: $(BIN)/go $(BIN)/golangci-lint $(BIN)/actionlint $(BIN)/shellcheck $(BIN)/yamlfmt $(BIN)/yamllint

# Setup Go
go_package_name := go$(go_version).$(os)-$(arch)
go_package_url  := https://go.dev/dl/$(go_package_name).tar.gz
go_install_path := $(BIN)/go-$(go_version)-$(os)-$(arch)

$(BIN)/go:
	@mkdir -p $(BIN)
	@mkdir -p $(GOPATH)
	@echo "Downloading Go $(go_version) to $(go_install_path)..."
	@curl --silent --show-error --fail --create-dirs --output-dir $(BIN) -O -L $(go_package_url)
	@tar -C $(BIN) -xzf $(BIN)/$(go_package_name).tar.gz && rm $(BIN)/$(go_package_name).tar.gz
	@mv $(BIN)/go $(go_install_path)
	@ln -s $(go_install_path)/bin/go $(BIN)/go

# Setup golangci
golangci_package_name := golangci-lint-$(golangci_version)-$(os)-$(arch)
golangci_package_url  := https://github.com/golangci/golangci-lint/releases/download/v$(golangci_version)/$(golangci_package_name).tar.gz
golangci_install_path := $(BIN)/$(golangci_package_name)

$(BIN)/golangci-lint:
	@mkdir -p $(BIN)
	@echo "Downloading golangci-lint $(golangci_version) to $(BIN)/golangci-lint-$(golangci_version)..." #TODO: Update this line to use golangci_install_path
	@curl --silent --show-error --fail --create-dirs --output-dir $(BIN) -O -L $(golangci_package_url)
	@tar -C $(BIN) -xzf $(BIN)/$(golangci_package_name).tar.gz && rm $(BIN)/$(golangci_package_name).tar.gz
	@ln -s $(golangci_install_path)/golangci-lint $(BIN)/golangci-lint

# Setup actionlint
actionlint_package_name := actionlint_$(actionlint_version)_$(os)_$(arch)
actionlint_package_url  := https://github.com/rhysd/actionlint/releases/download/v$(actionlint_version)/$(actionlint_package_name).tar.gz
actionlint_install_path := $(BIN)/$(actionlint_package_name)

$(BIN)/actionlint:
	@mkdir -p $(BIN)
	@echo "Downloading actionlint $(actionlint_version) to $(BIN)/actionlint-$(actionlint_version)..."
	@curl --silent --show-error --fail --create-dirs --output-dir $(BIN) -O -L $(actionlint_package_url)
	@mkdir -p $(actionlint_install_path) # actionlint isn't packaged in a directory
	@tar -C $(actionlint_install_path) -xzf $(BIN)/$(actionlint_package_name).tar.gz && rm $(BIN)/$(actionlint_package_name).tar.gz
	@ln -s $(actionlint_install_path)/actionlint $(BIN)/actionlint

# Setup shellcheck
shellcheck_package_name := shellcheck-v$(shellcheck_version).$(os).$(arch_alt)
shellcheck_package_url  := https://github.com/koalaman/shellcheck/releases/download/v$(shellcheck_version)/$(shellcheck_package_name).tar.xz
shellcheck_install_path := $(BIN)/shellcheck-v$(shellcheck_version)

$(BIN)/shellcheck:
	@mkdir -p $(BIN)
	@echo "Downloading shellcheck $(shellcheck_version) to $(BIN)/shellcheck-$(shellcheck_version)..."
	@curl --silent --show-error --fail --create-dirs --output-dir $(BIN) -O -L $(shellcheck_package_url)
	@tar -C $(BIN) -xf $(BIN)/$(shellcheck_package_name).tar.xz && rm $(BIN)/$(shellcheck_package_name).tar.xz
	@ln -s $(shellcheck_install_path)/shellcheck $(BIN)/shellcheck

# Setup yamlfmt
$(BIN)/yamlfmt: $(BIN)/go
	@mkdir -p $(BIN)
	@echo "Installing yamlfmt $(yamlfmt_version)..."
	@go install github.com/google/yamlfmt/cmd/yamlfmt@v$(yamlfmt_version)
	@ln -s $(GOPATH)/bin/yamlfmt $(BIN)/yamlfmt

# Setup yamllint
$(VENV)/bin/pip:
	@mkdir -p $(CACHE)
	@echo "Creating Python virtual environment at $(VENV)..."
	@$(PYTHON) -m venv $(VENV)

$(BIN)/yamllint: $(VENV)/bin/pip
	@mkdir -p $(BIN)
	@echo "Installing yamllint $(yamllint_version)..."
	@$(VENV)/bin/pip install --upgrade pip
	@$(VENV)/bin/pip install yamllint==$(yamllint_version)
	@ln -s $(VENV)/bin/yamllint $(BIN)/yamllint

.PHONY: update
update: $(BIN)/go
	@echo "Updating dependencies..."
	@go get -u
	@go mod tidy

.PHONY: build
build: $(BIN)/go
	@echo "Building..."
	@go build -o ./bin/ ./...

.PHONY: install
install: build
	@echo "Installing..."
	@go install ./...

.PHONY: format
format: tools
	@echo "Formatting..."
	@go fmt ./...
	@yamlfmt -conf .yamlfmt .github/workflows/*.yml

.PHONY: lint
lint: tools
	@echo "Linting..."
	@golangci-lint run ./...
	@actionlint
	@yamlfmt -conf .yamlfmt -lint .github/workflows/*.yml
	@yamllint --strict .github/workflows
	@find . -type f -name '*.sh' \
		-not -path './.git/*' \
		-not -path './.local/*' \
	| while IFS= read -r file; do shellcheck "$${file}"; done

.PHONY: test
test: $(BIN)/go
	@echo "Testing..."
	@go test ./... -count=1

.PHONY: clean
clean:
	@echo "Removing the $(CACHE) directory..."
	@go clean -modcache
	@rm -rf $(CACHE)
	@echo "Removing the $(BIN) directory..."
	@rm -rf $(BIN)
	@echo "Removing the $(PWD)/.local directory..."
	@if [ -d "$(PWD)/.local" ]; then rmdir "$(PWD)/.local"; fi
