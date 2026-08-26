# Registry is an email-gated onchain directory of Ethereum Foundation
# personnel.
#
# Configuration is loaded from `.env.maintainer` and can be overridden by
# `.env` or environment variables.
#
# Usage:
#   make build       # Build the contracts.
#   make test        # Run the contract test suite.
#   make deploy-dry  # Simulate the deployment without broadcasting.
#   make deploy      # Deploy the Registry via CreateX.
#   make deploy-verifier  # Deploy the immutable ZK Email verifier pair.
#   make zkey-verify CEREMONY_ZKEY=<path>  # Prove the vendored key honest.
#   make help        # Show all commands.

# Load configuration from `.env.maintainer` if it exists.
-include .env.maintainer

# Load configuration from `.env` if it exists.
-include .env

# `-include .env` loads the vars into make's scope but does NOT export them
# to recipe shells. The `${VAR:?msg}` checks and the `vm.env*` reads inside
# the forge script run in the shell, so the values must be exported for them
# to see.
export DOMAIN
export CREATEX
export VERIFIER
export MANAGEMENT
export SALT
export EXPECTED_ADDRESS
export GROTH16_VERIFIER_SALT
export GROTH16_VERIFIER_EXPECTED_ADDRESS
export VERIFIER_SALT
export VERIFIER_EXPECTED_ADDRESS
export DEPLOYER_PRIVATE_KEY
export RPC_URL
export ETHERSCAN_API_KEY
export MAINNET_RPC_URL
export MAINNET_FORK_BLOCK

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

.PHONY: build
build:
	@echo "Building contracts ..."
	cd contracts && forge build

.PHONY: test
test:
	@echo "Running contract tests ..."
	cd contracts && forge test --no-match-contract RegistryForkTest

.PHONY: test-fork
test-fork:
	@: $${MAINNET_RPC_URL:?must be set in .env}
	@echo "Running mainnet fork tests ..."
	cd contracts && forge test --match-contract RegistryForkTest -vv

.PHONY: coverage
coverage:
	@echo "Measuring test coverage ..."
	cd contracts && forge coverage --no-match-coverage "(script|test|vendor)" \
		--no-match-contract "RegistryForkTest|RegistryInvariant" \
		--report summary

.PHONY: clean
clean:
	@echo "Cleaning build artifacts ..."
	cd contracts && forge clean

# ---------------------------------------------------------------------------
# Circuits
# ---------------------------------------------------------------------------

# The ceremony's public artifact store: the p0tion S3 bucket of the "ZKEmail
# Ether Email Auth V1 Ceremony" (finalized December 28th, 2024; 67
# contributions on `emailauth`; compiled with circom 2.1.9).
CEREMONY_URL := https://zkemail-ether-email-auth-v1-ceremony-pse-p0tion-production.s3.eu-central-1.amazonaws.com

# The phase 1 the ceremony's zkeys build on: Perpetual Powers of Tau
# contribution 80, prepared at 2^23, pinned to the blake2b hash the ceremony
# records.
PTAU := ppot_0080_23.ptau
PTAU_URL := $(CEREMONY_URL)/pot/$(PTAU)
PTAU_B2 := 952221e636a2f8e09a9be9996587afefed2ebac5a1e9c74e812d41c4e58b3fce3b0d899ec698680ea4f00c4e36ada9f8fa491ad65d477020a9b5cabe69c3aca6

# The blake2b hash of the r1cs the ceremony's zkeys commit to; a local compile
# with circom 2.1.9 must reproduce it exactly.
R1CS_B2 := f6cf10b863c71a81cf166c4ff16e5113a5f27c08a619b8d82c30542057dd8e1f9392a20bca9a0344ed17a99d444a88221a49265a28c7313afd2acf6f7e25b752

# The ceremony's final zkey for `emailauth`; downloaded on demand unless the
# variable is overridden with a local path.
CEREMONY_ZKEY ?= circuits/build/emailauth_final.zkey

# The circom compiler; pass CIRCOM=/path/to/circom-2.1.9 to reproduce the
# ceremony's exact r1cs.
CIRCOM ?= circom

.PHONY: circuits-install
circuits-install:
	@echo "Installing pinned circuit dependencies ..."
	cd circuits && npm ci

# Compile the vendored email_auth circuit to r1cs. The r1cs depends on the
# circom compiler version; the ceremony compiled with circom 2.1.9, so pass
# CIRCOM=/path/to/circom-2.1.9 when the goal is reproducing its exact r1cs.
.PHONY: circuits
circuits:
	@command -v $(CIRCOM) >/dev/null || \
		{ echo "circom is required; see docs.circom.io"; exit 1; }
	@echo "Compiling email_auth with $$($(CIRCOM) --version) ..."
	cd circuits && mkdir -p build && $(CIRCOM) src/email_auth.circom \
		--r1cs --sym -l node_modules -o ./build
	cd circuits && NODE_OPTIONS=--max_old_space_size=16384 \
		npx snarkjs r1cs info build/email_auth.r1cs

.PHONY: ptau
ptau:
	@mkdir -p circuits/build
	@test -f circuits/build/$(PTAU) || { \
		echo "Downloading $(PTAU) (9.7 GB; resumable) ..."; \
		curl -L --retry 3 -C - -o circuits/build/$(PTAU) $(PTAU_URL); }
	@echo "$(PTAU_B2)  circuits/build/$(PTAU)" | b2sum -c -

# Prove the vendored verifying key honest, or catch it lying: verify the
# ceremony's final zkey against the compiled circuit and phase 1, export the
# Solidity verifier it implies, and diff that against
# `contracts/src/vendor/`. The zkey downloads from the ceremony's public
# bucket unless CEREMONY_ZKEY points at a local copy.
.PHONY: zkey-verify
zkey-verify: ptau
	@test -f circuits/build/email_auth.r1cs || \
		{ echo "run 'make circuits' first"; exit 1; }
	@echo "$(R1CS_B2)  circuits/build/email_auth.r1cs" | b2sum -c - || \
		{ echo "ABORT: the local r1cs is not the ceremony's, so it cannot"; \
		echo "prove the vendored source is the ceremony's circuit. Recompile"; \
		echo "with the ceremony's compiler (make circuits CIRCOM=circom-2.1.9)"; \
		echo "so the r1cs blake2b matches R1CS_B2, then rerun."; exit 1; }
	@test -f $(CEREMONY_ZKEY) || { \
		echo "Downloading the ceremony's final emailauth zkey (3.1 GB) ..."; \
		curl -L --retry 3 -C - -o $(CEREMONY_ZKEY) \
			$(CEREMONY_URL)/circuits/emailauth/contributions/emailauth_final.zkey; }
	@echo "Verifying the ceremony zkey against the circuit and phase 1 ..."
	cd circuits && NODE_OPTIONS=--max_old_space_size=131072 \
		npx snarkjs zkey verify \
		build/email_auth.r1cs build/$(PTAU) $(abspath $(CEREMONY_ZKEY))
	@echo "Exporting the zkey's verifying key as a Solidity verifier ..."
	cd circuits && NODE_OPTIONS=--max_old_space_size=16384 \
		npx snarkjs zkey export solidityverifier \
		$(abspath $(CEREMONY_ZKEY)) build/Groth16Verifier.ceremony.sol
	@if diff -q contracts/src/vendor/Groth16Verifier.sol \
		circuits/build/Groth16Verifier.ceremony.sol > /dev/null; then \
		echo "VENDORED VERIFIER MATCHES THE CEREMONY ZKEY."; \
	else \
		echo "VENDORED VERIFIER DIFFERS FROM THE CEREMONY ZKEY."; \
		echo "Replace contracts/src/vendor/Groth16Verifier.sol with"; \
		echo "circuits/build/Groth16Verifier.ceremony.sol before deployment."; \
		exit 1; \
	fi

# Build a development zkey for local end-to-end proof testing. It is NOT the
# ceremony key and must never back a production verifier.
.PHONY: zkey-dev
zkey-dev: ptau
	@test -f circuits/build/email_auth.r1cs || \
		{ echo "run 'make circuits' first"; exit 1; }
	@echo "Building a development zkey (NOT for production) ..."
	cd circuits && NODE_OPTIONS=--max_old_space_size=131072 \
		npx snarkjs groth16 setup \
		build/email_auth.r1cs build/$(PTAU) build/email_auth_dev.zkey

# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------

# Fail fast with a pointer to the right file when deployment configuration
# is missing. `SALT` / `EXPECTED_ADDRESS` come from grinding CreateX salts
# (e.g. with createXcrunch) so the Registry lands at a known address; see
# `.env.example`.
.PHONY: check-deploy-config
check-deploy-config:
	@: $${RPC_URL:?must be set in .env}
	@: $${DEPLOYER_PRIVATE_KEY:?must be set in .env}
	@: $${SALT:?must be set in .env (grind one with createXcrunch)}
	@: $${EXPECTED_ADDRESS:?must be set in .env (the address the salt grinds to)}
	@: $${VERIFIER:?must be set in .env (the ZK Email proof verifier)}
	@: $${MANAGEMENT:?must be set in .env}
	@: $${CREATEX:?must be set in .env.maintainer}
	@: $${DOMAIN:?must be set in .env.maintainer}

.PHONY: deploy-dry
deploy-dry: check-deploy-config
	@echo "Simulating Registry deployment ..."
	@echo "  RPC:              $(RPC_URL)"
	@echo "  Expected address: $(EXPECTED_ADDRESS)"
	cd contracts && forge script script/Deploy.s.sol --rpc-url $(RPC_URL)

.PHONY: deploy
deploy: check-deploy-config
	@: $${ETHERSCAN_API_KEY:?must be set in .env (deploys also verify)}
	@echo "Deploying Registry ..."
	@echo "  RPC:              $(RPC_URL)"
	@echo "  Expected address: $(EXPECTED_ADDRESS)"
	cd contracts && forge script script/Deploy.s.sol \
		--rpc-url $(RPC_URL) \
		--broadcast --slow \
		--verify \
		--etherscan-api-key $(ETHERSCAN_API_KEY)

# The immutable ZK Email verifier pair: the vendored, snarkjs-generated
# Groth16Verifier holding the circuit's verifying key, and the immutable
# Verifier pinned to it. Deployed before the Registry, which is then
# constructed against the Verifier's address (`VERIFIER` in `.env`).
.PHONY: check-verifier-config
check-verifier-config:
	@: $${RPC_URL:?must be set in .env}
	@: $${DEPLOYER_PRIVATE_KEY:?must be set in .env}
	@: $${GROTH16_VERIFIER_SALT:?must be set in .env}
	@: $${GROTH16_VERIFIER_EXPECTED_ADDRESS:?must be set in .env}
	@: $${VERIFIER_SALT:?must be set in .env}
	@: $${VERIFIER_EXPECTED_ADDRESS:?must be set in .env}
	@: $${CREATEX:?must be set in .env.maintainer}

.PHONY: deploy-verifier-dry
deploy-verifier-dry: check-verifier-config
	@echo "Simulating verifier pair deployment ..."
	@echo "  RPC:                      $(RPC_URL)"
	@echo "  Expected Groth16Verifier: $(GROTH16_VERIFIER_EXPECTED_ADDRESS)"
	@echo "  Expected Verifier:        $(VERIFIER_EXPECTED_ADDRESS)"
	cd contracts && forge script script/DeployVerifier.s.sol --rpc-url $(RPC_URL)

.PHONY: deploy-verifier
deploy-verifier: check-verifier-config
	@: $${ETHERSCAN_API_KEY:?must be set in .env (deploys also verify)}
	@echo "Deploying the immutable verifier pair ..."
	@echo "  RPC:                      $(RPC_URL)"
	@echo "  Expected Groth16Verifier: $(GROTH16_VERIFIER_EXPECTED_ADDRESS)"
	@echo "  Expected Verifier:        $(VERIFIER_EXPECTED_ADDRESS)"
	cd contracts && forge script script/DeployVerifier.s.sol \
		--rpc-url $(RPC_URL) \
		--broadcast --slow \
		--verify \
		--etherscan-api-key $(ETHERSCAN_API_KEY)

.PHONY: verify-verifier
verify-verifier:
	@: $${RPC_URL:?must be set in .env}
	@: $${ETHERSCAN_API_KEY:?must be set in .env}
	@: $${GROTH16_VERIFIER_EXPECTED_ADDRESS:?must be set in .env}
	@: $${VERIFIER_EXPECTED_ADDRESS:?must be set in .env}
	@echo "Verifying the verifier pair ..."
	cd contracts && forge verify-contract \
		--rpc-url $(RPC_URL) \
		--etherscan-api-key $(ETHERSCAN_API_KEY) \
		--watch \
		$(GROTH16_VERIFIER_EXPECTED_ADDRESS) \
		src/vendor/Groth16Verifier.sol:Groth16Verifier
	cd contracts && forge verify-contract \
		--rpc-url $(RPC_URL) \
		--etherscan-api-key $(ETHERSCAN_API_KEY) \
		--constructor-args $$(cast abi-encode "constructor(address)" \
			$(GROTH16_VERIFIER_EXPECTED_ADDRESS)) \
		--watch \
		$(VERIFIER_EXPECTED_ADDRESS) \
		src/Verifier.sol:Verifier

# Contracts deployed through the CreateX factory surface as internal CREATE
# traces, which explorers and forge's post-broadcast verification sometimes
# miss. This standalone goal re-verifies the deployed registry directly, with
# the constructor arguments recomputed from configuration.
.PHONY: verify
verify:
	@: $${RPC_URL:?must be set in .env}
	@: $${ETHERSCAN_API_KEY:?must be set in .env}
	@: $${EXPECTED_ADDRESS:?must be set in .env}
	@: $${VERIFIER:?must be set in .env}
	@: $${MANAGEMENT:?must be set in .env}
	@: $${DOMAIN:?must be set in .env.maintainer}
	@echo "Verifying Registry at $(EXPECTED_ADDRESS) ..."
	cd contracts && forge verify-contract \
		--rpc-url $(RPC_URL) \
		--etherscan-api-key $(ETHERSCAN_API_KEY) \
		--constructor-args $$(cast abi-encode \
			"constructor(address,string,address)" \
			$(VERIFIER) "$(DOMAIN)" $(MANAGEMENT)) \
		--watch \
		$(EXPECTED_ADDRESS) \
		src/Registry.sol:Registry

.PHONY: help
help:
	@echo "Registry"
	@echo ""
	@echo "  build        Build the contracts."
	@echo "  test         Run the unit test suite."
	@echo "  test-fork    Run the mainnet fork tests (needs MAINNET_RPC_URL)."
	@echo "  coverage     Measure test coverage of the contracts."
	@echo "  clean        Clean build artifacts."
	@echo ""
	@echo "  circuits-install     Install the pinned circuit dependencies."
	@echo "  circuits             Compile the vendored email_auth circuit."
	@echo "  zkey-verify          Verify a ceremony zkey; diff its verifier."
	@echo "  zkey-dev             Build a development zkey (never production)."
	@echo ""
	@echo "  deploy-verifier-dry  Simulate the verifier pair deployment."
	@echo "  deploy-verifier      Deploy the immutable ZK Email verifier pair."
	@echo "  verify-verifier      Re-verify the deployed verifier pair."
	@echo ""
	@echo "  deploy-dry   Simulate the Registry deployment without broadcasting."
	@echo "  deploy       Deploy the Registry via CreateX, then verify it."
	@echo "  verify       Re-verify an already-deployed Registry."
	@echo "  help         Show this help message."
	@echo ""
	@echo "Deployment workflow:"
	@echo "  # Set in .env (copy .env.example and fill in):"
	@echo "  #   RPC_URL, DEPLOYER_PRIVATE_KEY, SALT, EXPECTED_ADDRESS,"
	@echo "  #   GROTH16_VERIFIER_SALT/_EXPECTED_ADDRESS, VERIFIER_SALT/"
	@echo "  #   _EXPECTED_ADDRESS, VERIFIER, MANAGEMENT, ETHERSCAN_API_KEY"
	@echo "  # Project-pinned defaults in .env.maintainer (committed):"
	@echo "  #   DOMAIN, CREATEX"
	@echo "  make deploy-verifier  # Deploy the immutable verifier pair first."
	@echo "  make deploy-dry  # Simulate; verifies the CreateX address matches."
	@echo "  make deploy      # Broadcast the deployment and verify the source."
	@echo "  make verify      # Re-verify if explorer verification lagged."
	@echo ""

.DEFAULT_GOAL := help
