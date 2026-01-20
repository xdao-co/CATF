.PHONY: help all build build-cascli clean test test-unit test-integration fmt vet regen-conformance examples examples-ipfs example-uc1 example-uc2 example-uc3 example-uc4 example-uc1-ipfs example-uc2-ipfs example-uc3-ipfs example-uc4-ipfs walkthrough walkthrough-all walkthrough-localfs walkthrough-ipfs walkthrough-grpc walkthrough-grpc-localfs walkthrough-grpc-ipfs

SHELL := /bin/bash

GO ?= go
SRC_DIR := src
BIN_DIR := bin

CATF_BIN := $(BIN_DIR)/xdao-catf
CASCLI_BIN := $(BIN_DIR)/xdao-cascli

help:
	@echo "Targets:"
	@echo "  build            Build $(CATF_BIN)"
	@echo "  clean            Remove ./$(BIN_DIR)"
	@echo "  test             Run unit tests (default build tags)"
	@echo "  test-unit        Alias for test"
	@echo "  test-integration Run integration tests (build tag: integration)"
	@echo "  regen-conformance Regenerate src/testdata/conformance fixtures"
	@echo "  fmt              Format Go code"
	@echo "  vet              Run go vet"
	@echo "  examples         Run all example scripts"
	@echo "  examples-ipfs    Run all example scripts (stores subjects in local IPFS repo)"
	@echo "  example-uc1      Run examples/usecase1_document_publishing.sh"
	@echo "  example-uc2      Run examples/usecase2_real_estate_good_faith_money.sh"
	@echo "  example-uc3      Run examples/usecase3_science_quorum.sh"
	@echo "  example-uc4      Run examples/usecase4_kms_lite_key_management.sh"
	@echo "  example-uc1-ipfs Like example-uc1, but with XDAO_USE_IPFS=1"
	@echo "  example-uc2-ipfs Like example-uc2, but with XDAO_USE_IPFS=1"
	@echo "  example-uc3-ipfs Like example-uc3, but with XDAO_USE_IPFS=1"
	@echo "  example-uc4-ipfs Like example-uc4, but with XDAO_USE_IPFS=1"
	@echo "  walkthrough      Run storage walkthroughs (localfs + ipfs)"
	@echo "  walkthrough-all  Store subject+policy+attestations+CROF in localfs + ipfs (write_policy=all)"
	@echo "  walkthrough-localfs Store subject+policy+attestations+CROF via downloaded LocalFS plugin daemon (CAS gRPC)"
	@echo "  walkthrough-ipfs Store subject+policy+attestations+CROF via downloaded IPFS plugin daemon (CAS gRPC)"
	@echo "  walkthrough-grpc Run storage walkthroughs via downloaded plugin daemons (localfs + ipfs)"
	@echo "  walkthrough-grpc-localfs Alias for walkthrough-localfs"
	@echo "  walkthrough-grpc-ipfs Alias for walkthrough-ipfs"

all: build test

$(BIN_DIR):
	@mkdir -p "$(BIN_DIR)"

build: $(BIN_DIR)
	$(GO) -C "$(SRC_DIR)" build -o "../$(CATF_BIN)" ./cmd/xdao-catf

build-cascli: $(BIN_DIR)
	$(GO) -C "$(SRC_DIR)" build -o "../$(CASCLI_BIN)" ./internal/tools/cascli

clean:
	@rm -rf "$(BIN_DIR)"

test: test-unit

test-unit:
	$(GO) -C "$(SRC_DIR)" test ./...

test-integration:
	$(GO) -C "$(SRC_DIR)" test -tags=integration ./...

regen-conformance:
	bash "$(SRC_DIR)/scripts/regen-conformance.sh"

fmt:
	$(GO) -C "$(SRC_DIR)" fmt ./...

vet:
	$(GO) -C "$(SRC_DIR)" vet ./...

examples: example-uc1 example-uc2 example-uc3 example-uc4

examples-ipfs: example-uc1-ipfs example-uc2-ipfs example-uc3-ipfs example-uc4-ipfs

example-uc1: build
	bash examples/usecase1_document_publishing.sh

example-uc1-ipfs: build
	XDAO_USE_IPFS=1 bash examples/usecase1_document_publishing.sh

example-uc2: build
	bash examples/usecase2_real_estate_good_faith_money.sh

example-uc2-ipfs: build
	XDAO_USE_IPFS=1 bash examples/usecase2_real_estate_good_faith_money.sh

example-uc3: build
	bash examples/usecase3_science_quorum.sh

example-uc3-ipfs: build
	XDAO_USE_IPFS=1 bash examples/usecase3_science_quorum.sh

example-uc4: build
	bash examples/usecase4_kms_lite_key_management.sh

example-uc4-ipfs: build
	XDAO_USE_IPFS=1 bash examples/usecase4_kms_lite_key_management.sh

walkthrough: walkthrough-localfs walkthrough-ipfs

walkthrough-all: build build-cascli
	bash examples/walkthrough_all.sh

walkthrough-localfs: build build-cascli
	bash examples/walkthrough_localfs.sh

walkthrough-ipfs: build build-cascli
	bash examples/walkthrough_ipfs.sh

walkthrough-grpc: walkthrough-grpc-localfs walkthrough-grpc-ipfs

walkthrough-grpc-localfs: build build-cascli
	bash examples/walkthrough_grpccas_localfs.sh

walkthrough-grpc-ipfs: build build-cascli
	bash examples/walkthrough_grpccas_ipfs.sh
