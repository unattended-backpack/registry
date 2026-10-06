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
#   make deploy-verifier  # Deploy the immutable email verifier pair.
#   make verifier-check   # Prove the vendored verifier is the circuit's.
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
export HONK_VERIFIER_SALT
export HONK_VERIFIER_EXPECTED_ADDRESS
export VERIFIER_SALT
export VERIFIER_EXPECTED_ADDRESS
export RELATIONS_LIB
export ZK_TRANSCRIPT_LIB
export DEPLOYER_PRIVATE_KEY
export RPC_URL
export ETHERSCAN_API_KEY
export FORK_BLOCK

# The deployer's address, derived from its key when a recipe runs. Forge must
# be told the sender outright: it deploys the HonkVerifier's linked libraries
# from the sender, and refuses to broadcast from its default one. Secrets
# reach recipes only through the environment, so make never echoes them.
DEPLOYER_ADDRESS = $$(cast wallet address --private-key "$$DEPLOYER_PRIVATE_KEY")

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
	@: $${RPC_URL:?must be set in .env}
	@echo "Running fork tests against the RPC_URL chain ..."
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
# Toolchain
# ---------------------------------------------------------------------------

# The pinned proving toolchain: Barretenberg 5.2.0 and the Noir compiler it
# pins (1.0.0-beta.25, git 75061fab). Both install into `.toolchain/`, never
# over a global install, and each download is checked against its SHA-256.
NARGO_VERSION := 1.0.0-beta.25
NARGO_URL := https://github.com/noir-lang/noir/releases/download/v$(NARGO_VERSION)/nargo-x86_64-unknown-linux-gnu.tar.gz
NARGO_SHA256 := bf3410ab94933a4aebd1f988b67ae974c6c227f9456ed0f1e4a3716bb8a30fe9
BB_VERSION := 5.2.0
BB_URL := https://github.com/AztecProtocol/aztec-packages/releases/download/v$(BB_VERSION)/barretenberg-amd64-linux.tar.gz
BB_SHA256 := 17ab8476961728cdc5c69b6c4ff427c9092cef11d1e0b0166929a0417dfa7cfb
TOOLCHAIN := $(abspath .toolchain)
NARGO := $(TOOLCHAIN)/bin/nargo
BB := $(TOOLCHAIN)/bin/bb

.PHONY: toolchain
toolchain:
	@mkdir -p $(TOOLCHAIN)/dl $(TOOLCHAIN)/bin
	@test -f $(TOOLCHAIN)/dl/nargo.tar.gz || \
		curl -L --fail -o $(TOOLCHAIN)/dl/nargo.tar.gz $(NARGO_URL)
	@echo "$(NARGO_SHA256)  $(TOOLCHAIN)/dl/nargo.tar.gz" | sha256sum -c -
	@test -f $(TOOLCHAIN)/dl/bb.tar.gz || \
		curl -L --fail -o $(TOOLCHAIN)/dl/bb.tar.gz $(BB_URL)
	@echo "$(BB_SHA256)  $(TOOLCHAIN)/dl/bb.tar.gz" | sha256sum -c -
	tar xzf $(TOOLCHAIN)/dl/nargo.tar.gz -C $(TOOLCHAIN)/bin
	tar xzf $(TOOLCHAIN)/dl/bb.tar.gz -C $(TOOLCHAIN)/bin
	$(NARGO) --version
	$(BB) --version

# ---------------------------------------------------------------------------
# Circuits
# ---------------------------------------------------------------------------

# The artifacts the circuit implies, and where they are vendored: the
# UltraHonk verifier the contracts deploy, and the compiled circuit the
# frontend proves with (stripped of debug information).
CIRCUIT_JSON := circuits/target/email_proof.json
VENDORED_VERIFIER := contracts/src/vendor/HonkVerifier.sol
VENDORED_CIRCUIT := frontend/circuit/email_proof.json

.PHONY: circuits-install
circuits-install:
	@echo "Installing pinned circuit tooling ..."
	cd circuits && npm ci

# Compile the email circuit and the DKIM key hash program.
.PHONY: circuits
circuits:
	@test -x $(NARGO) || { echo "run 'make toolchain' first"; exit 1; }
	cd circuits && $(NARGO) compile --workspace

# Run the circuit and input generator tests.
.PHONY: circuits-test
circuits-test: circuits
	cd circuits && npm test

# Derive the verification key and the Solidity verifier from the compiled
# circuit, into `circuits/target/`.
.PHONY: verifier
verifier: circuits
	@mkdir -p circuits/target/vk
	$(BB) write_vk -b $(CIRCUIT_JSON) -o circuits/target/vk -t evm
	$(BB) write_solidity_verifier -k circuits/target/vk/vk \
		-o circuits/target/HonkVerifier.sol -t evm

# Vendor the derived verifier into the contracts and the compiled circuit
# into the frontend.
.PHONY: vendor
vendor: verifier
	cp circuits/target/HonkVerifier.sol $(VENDORED_VERIFIER)
	@mkdir -p $(dir $(VENDORED_CIRCUIT))
	node -e 'const f=require("fs");const c=JSON.parse(f.readFileSync("$(CIRCUIT_JSON)"));f.writeFileSync("$(VENDORED_CIRCUIT)",JSON.stringify({noir_version:c.noir_version,hash:c.hash,abi:c.abi,bytecode:c.bytecode}))'
	@echo "Vendored $(VENDORED_VERIFIER) and $(VENDORED_CIRCUIT)."

# Prove the vendored artifacts honest, or catch them lying: recompile the
# circuit from source with the pinned toolchain, derive its verifier, and
# require both vendored artifacts to match byte for byte.
.PHONY: verifier-check
verifier-check: verifier
	@if diff -q $(VENDORED_VERIFIER) circuits/target/HonkVerifier.sol > /dev/null; then \
		echo "VENDORED VERIFIER MATCHES THE CIRCUIT."; \
	else \
		echo "VENDORED VERIFIER DIFFERS FROM THE CIRCUIT. Run 'make vendor'."; \
		exit 1; \
	fi
	@node -e 'const f=require("fs");const a=JSON.parse(f.readFileSync("$(CIRCUIT_JSON)"));const b=JSON.parse(f.readFileSync("$(VENDORED_CIRCUIT)"));process.exit(a.bytecode===b.bytecode&&JSON.stringify(a.abi)===JSON.stringify(b.abi)?0:1)' \
		&& echo "VENDORED FRONTEND CIRCUIT MATCHES THE CIRCUIT." \
		|| { echo "VENDORED FRONTEND CIRCUIT DIFFERS. Run 'make vendor'."; exit 1; }

# The browser prover: bb.js and noir_js bundled (with Barretenberg's CDN
# reference-string loader swapped for one that reads files shipped with the
# site), and the first 2^18 compressed BN254 reference points plus the G2
# point, fetched once from Aztec's CDN and pinned by hash. The points only
# serve the prover: soundness rests on the verification key and G2 point
# baked into the on-chain HonkVerifier, so wrong points can only produce
# proofs that fail.
CRS_URL := https://crs.aztec-cdn.foundation
CRS_POINTS := 262144
CRS_G1_SHA256 := 5107a7926d504236331b4872b7218a1ca18921b5358d894822576e1aeb684934
CRS_G2_SHA256 := 01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f

.PHONY: frontend-vendor
frontend-vendor: vendor
	rm -rf frontend/vendor/prover
	cd circuits && node scripts/bundle-prover.mjs
	@mkdir -p frontend/crs
	@test -f frontend/crs/bn254_g1_compressed.dat || \
		curl -L --fail -H "Range: bytes=0-$$(( $(CRS_POINTS) * 32 - 1 ))" \
			-o frontend/crs/bn254_g1_compressed.dat $(CRS_URL)/g1_compressed.dat
	@test -f frontend/crs/bn254_g2.dat || \
		curl -L --fail -o frontend/crs/bn254_g2.dat $(CRS_URL)/g2.dat
	@echo "$(CRS_G1_SHA256)  frontend/crs/bn254_g1_compressed.dat" | sha256sum -c -
	@echo "$(CRS_G2_SHA256)  frontend/crs/bn254_g2.dat" | sha256sum -c -

# The subject line that authorizes CONTROLLER for a private profile on the
# Registry at REGISTRY on chain CHAIN_ID: make subject CONTROLLER=<address>
# CHAIN_ID=<id> REGISTRY=<address> [SALT=<secret>] [EMAIL=<address>]. Without
# SALT a fresh secret is generated; keep it, since renewals need it.
.PHONY: subject
subject:
	@: $${CONTROLLER:?usage: make subject CONTROLLER=<address> CHAIN_ID=<id> REGISTRY=<address> [SALT=<secret>] [EMAIL=<address>]}
	@: $${CHAIN_ID:?CHAIN_ID is required}
	@: $${REGISTRY:?REGISTRY is required}
	@cd circuits && node scripts/subject.mjs --controller $(CONTROLLER) \
		--chain-id $(CHAIN_ID) --registry $(REGISTRY) \
		$(if $(SALT),--salt $(SALT)) $(if $(EMAIL),--email $(EMAIL))

# Verify, from Aztec's public transcripts, that the Registry's proofs rest on
# the AZTEC Ignition ceremony: the chain of all 176 contributions, the sealed
# tau baked into the vendored verifier and the frontend, the structure of the
# 2^18 reference points, and bb's derivation of the vendored verifier from
# those points alone, with no network. SIGNERS=<address>[,<address>...] (or
# SIGNERS=all) also checks those participants' signatures over their full
# transcripts, streamed. Downloads cache under .toolchain/ignition/.
.PHONY: ignition-verify
ignition-verify: circuits
	cd circuits && node scripts/ignition-verify.mjs $(if $(SIGNERS),--signers $(SIGNERS))

# Prove an email from the command line: make prove EML=<email.eml>
# SALT=<secret> CONTROLLER=<address> CHAIN_ID=<id> REGISTRY=<address>
# [KEY=<dkim.txt>] [OUT=<proof.json>]. Without KEY, the DKIM key is looked up
# in DNS through this machine's resolver.
.PHONY: prove
prove:
	@: $${EML:?usage: make prove EML=<email.eml> SALT=<secret> CONTROLLER=<address> CHAIN_ID=<id> REGISTRY=<address> [KEY=<dkim.txt>] [OUT=<proof.json>]}
	@: $${SALT:?SALT is required}
	@: $${CONTROLLER:?CONTROLLER is required}
	@: $${CHAIN_ID:?CHAIN_ID is required}
	@: $${REGISTRY:?REGISTRY is required}
	cd circuits && node scripts/prove.mjs "$(abspath $(EML))" \
		--salt $(SALT) --controller $(CONTROLLER) --chain-id $(CHAIN_ID) \
		--registry $(REGISTRY) --domain $(DOMAIN) \
		$(if $(KEY),--key "$(abspath $(KEY))") \
		$(if $(OUT),--out "$(abspath $(OUT))")

# Regenerate the proof vectors the contract tests load, from the synthetic
# emails and, when present, the real ones (see circuits/scripts/make-vectors.mjs).
.PHONY: vectors
vectors: circuits
	cd circuits && node scripts/make-vectors.mjs

# A local chain for the demo. By default anvil starts at the fixture emails'
# time (an hour after the latest of them), so they stay usable however old
# they are; DEMO_TIME=now starts it at wall-clock time, for emails sent today,
# and DEMO_TIME=<unix seconds> at any other moment. Port 8545 by default
# (DEMO_PORT).
DEMO_PORT ?= 8545
DEMO_RPC_URL ?= http://127.0.0.1:$(DEMO_PORT)
DEMO_TIME ?= fixtures
DEMO_SELECTOR ?= gmail
ANVIL_1 := 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
ANVIL_1_KEY := 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

.PHONY: demo-anvil
demo-anvil:
	anvil --port $(DEMO_PORT) $(if $(filter now,$(DEMO_TIME)),,--timestamp \
		$(if $(filter fixtures,$(DEMO_TIME)),$$(cd circuits && node scripts/fixture-time.mjs),$(DEMO_TIME)))

# Deploy a demonstration Registry onto the demo chain (run `make demo-anvil`
# in another terminal first). It honors the domain's live DKIM key and the
# throwaway key the synthetic fixture emails are signed with. The Registry
# lands at 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 on chain 31337.
.PHONY: demo-deploy
demo-deploy:
	@LIVE=$$(cd circuits && node scripts/key-hash.mjs $(DEMO_SELECTOR)._domainkey.$(DOMAIN)) && \
		TEST=$$(cd circuits && node scripts/key-hash.mjs --file test/fixtures/test-dkim.txt) && \
		echo "Honoring $(DEMO_SELECTOR)._domainkey.$(DOMAIN) ($$LIVE) and the test key ($$TEST)" && \
		cd contracts && DEMO_KEY_HASHES=$$LIVE,$$TEST forge script \
			script/DeployLocal.s.sol --rpc-url $(DEMO_RPC_URL) --broadcast \
			--sender $(ANVIL_1) --private-key $(ANVIL_1_KEY)

# Deploy a demonstration Registry onto any chain but mainnet, from a funded
# key: `make demo-deploy-chain DEMO_RPC_URL=<rpc> DEMO_PRIVATE_KEY=<key>`. The
# key's account deploys the verifier stack and the Registry, and is its
# management. It honors the domain's live DKIM key only. Nothing is pinned,
# so emails for this Registry name its chain and the address it prints; the
# fixture emails name the local anvil and cannot act here.
.PHONY: demo-deploy-chain
demo-deploy-chain:
	@: $${DEMO_PRIVATE_KEY:?set DEMO_PRIVATE_KEY to a funded key on the target chain}
	@LIVE=$$(cd circuits && node scripts/key-hash.mjs $(DEMO_SELECTOR)._domainkey.$(DOMAIN)) && \
		SENDER=$$(cast wallet address --private-key "$$DEMO_PRIVATE_KEY") && \
		echo "Deploying from $$SENDER to $(DEMO_RPC_URL)" && \
		echo "Honoring $(DEMO_SELECTOR)._domainkey.$(DOMAIN) ($$LIVE)" && \
		cd contracts && DEMO_KEY_HASHES=$$LIVE forge script \
			script/DeployDemo.s.sol --rpc-url $(DEMO_RPC_URL) --broadcast --slow \
			--sender $$SENDER --private-key "$$DEMO_PRIVATE_KEY"

# The end-to-end test: the real frontend in headless Chromium against its own
# anvil (started at the fixture emails' time), through register, records,
# renewal, and rotation, for the synthetic emails and the real ones when
# present. Needs Chromium (CHROME=<binary> to choose one).
.PHONY: e2e
e2e: circuits
	cd circuits && node test/e2e.mjs

# Compute the DKIM key hash management honors:
# make key-hash SELECTOR=gmail (looks up <SELECTOR>._domainkey.<DOMAIN>).
.PHONY: key-hash
key-hash:
	@: $${SELECTOR:?usage: make key-hash SELECTOR=<dkim selector>}
	@cd circuits && node scripts/key-hash.mjs $(SELECTOR)._domainkey.$(DOMAIN)

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
	@: $${VERIFIER:?must be set in .env (the email proof verifier)}
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
		--etherscan-api-key $$ETHERSCAN_API_KEY

# The immutable email verifier pair: the vendored, Barretenberg-generated
# HonkVerifier holding the circuit's verification key, and the immutable
# Verifier pinned to it. Deployed before the Registry, which is then
# constructed against the Verifier's address (`VERIFIER` in `.env`).
.PHONY: check-verifier-config
check-verifier-config:
	@: $${RPC_URL:?must be set in .env}
	@: $${DEPLOYER_PRIVATE_KEY:?must be set in .env}
	@: $${HONK_VERIFIER_SALT:?must be set in .env}
	@: $${HONK_VERIFIER_EXPECTED_ADDRESS:?must be set in .env}
	@: $${VERIFIER_SALT:?must be set in .env}
	@: $${VERIFIER_EXPECTED_ADDRESS:?must be set in .env}
	@: $${CREATEX:?must be set in .env.maintainer}

.PHONY: deploy-verifier-dry
deploy-verifier-dry: check-verifier-config
	@echo "Simulating verifier pair deployment ..."
	@echo "  RPC:                      $(RPC_URL)"
	@echo "  Expected HonkVerifier: $(HONK_VERIFIER_EXPECTED_ADDRESS)"
	@echo "  Expected Verifier:     $(VERIFIER_EXPECTED_ADDRESS)"
	cd contracts && forge script script/DeployVerifier.s.sol --rpc-url $(RPC_URL) \
		--sender $(DEPLOYER_ADDRESS)

.PHONY: deploy-verifier
deploy-verifier: check-verifier-config
	@: $${ETHERSCAN_API_KEY:?must be set in .env (deploys also verify)}
	@echo "Deploying the immutable verifier pair ..."
	@echo "  RPC:                   $(RPC_URL)"
	@echo "  Expected HonkVerifier: $(HONK_VERIFIER_EXPECTED_ADDRESS)"
	@echo "  Expected Verifier:     $(VERIFIER_EXPECTED_ADDRESS)"
	cd contracts && forge script script/DeployVerifier.s.sol \
		--rpc-url $(RPC_URL) \
		--sender $(DEPLOYER_ADDRESS) \
		--broadcast --slow \
		--verify \
		--etherscan-api-key $$ETHERSCAN_API_KEY

# Contracts deployed through the CreateX factory surface as internal CREATE
# traces, which explorers and forge's post-broadcast verification sometimes
# miss. This goal re-verifies the whole deployed stack directly, with every
# constructor argument recomputed from configuration: the HonkVerifier's two
# linked libraries (RelationsLib and ZKTranscriptLib, which forge deploys from
# the deployer ahead of it; deploy-verifier prints their addresses), the
# HonkVerifier, the Verifier, and the Registry.
HONK_LIBRARIES := \
	--libraries src/vendor/HonkVerifier.sol:RelationsLib:$(RELATIONS_LIB) \
	--libraries src/vendor/HonkVerifier.sol:ZKTranscriptLib:$(ZK_TRANSCRIPT_LIB)

.PHONY: verify
verify:
	@: $${RPC_URL:?must be set in .env}
	@: $${ETHERSCAN_API_KEY:?must be set in .env}
	@: $${RELATIONS_LIB:?must be set in .env (printed by deploy-verifier)}
	@: $${ZK_TRANSCRIPT_LIB:?must be set in .env (printed by deploy-verifier)}
	@: $${HONK_VERIFIER_EXPECTED_ADDRESS:?must be set in .env}
	@: $${VERIFIER_EXPECTED_ADDRESS:?must be set in .env}
	@: $${EXPECTED_ADDRESS:?must be set in .env}
	@: $${VERIFIER:?must be set in .env}
	@: $${MANAGEMENT:?must be set in .env}
	@: $${DOMAIN:?must be set in .env.maintainer}
	@echo "Verifying the HonkVerifier's libraries ..."
	cd contracts && forge verify-contract \
		--rpc-url $(RPC_URL) \
		--etherscan-api-key $$ETHERSCAN_API_KEY \
		--watch \
		$(RELATIONS_LIB) \
		src/vendor/HonkVerifier.sol:RelationsLib
	cd contracts && forge verify-contract \
		--rpc-url $(RPC_URL) \
		--etherscan-api-key $$ETHERSCAN_API_KEY \
		--watch \
		$(ZK_TRANSCRIPT_LIB) \
		src/vendor/HonkVerifier.sol:ZKTranscriptLib
	@echo "Verifying HonkVerifier at $(HONK_VERIFIER_EXPECTED_ADDRESS) ..."
	cd contracts && forge verify-contract \
		--rpc-url $(RPC_URL) \
		--etherscan-api-key $$ETHERSCAN_API_KEY \
		--watch \
		$(HONK_LIBRARIES) \
		$(HONK_VERIFIER_EXPECTED_ADDRESS) \
		src/vendor/HonkVerifier.sol:HonkVerifier
	@echo "Verifying Verifier at $(VERIFIER_EXPECTED_ADDRESS) ..."
	cd contracts && forge verify-contract \
		--rpc-url $(RPC_URL) \
		--etherscan-api-key $$ETHERSCAN_API_KEY \
		--constructor-args $$(cast abi-encode "constructor(address)" \
			$(HONK_VERIFIER_EXPECTED_ADDRESS)) \
		--watch \
		$(VERIFIER_EXPECTED_ADDRESS) \
		src/Verifier.sol:Verifier
	@echo "Verifying Registry at $(EXPECTED_ADDRESS) ..."
	cd contracts && forge verify-contract \
		--rpc-url $(RPC_URL) \
		--etherscan-api-key $$ETHERSCAN_API_KEY \
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
	@echo "  test-fork    Rehearse deployment on a fork of the RPC_URL chain."
	@echo "  coverage     Measure test coverage of the contracts."
	@echo "  clean        Clean build artifacts."
	@echo ""
	@echo "  toolchain            Install the pinned nargo and bb into .toolchain/."
	@echo "  circuits-install     Install the pinned circuit tooling (npm ci)."
	@echo "  circuits             Compile the email circuit."
	@echo "  circuits-test        Run the circuit and input generator tests."
	@echo "  verifier             Derive the verification key and verifier."
	@echo "  vendor               Vendor the verifier and the frontend circuit."
	@echo "  verifier-check       Prove the vendored artifacts are the circuit's."
	@echo "  ignition-verify      Verify the Ignition ceremony our verifier rests on: [SIGNERS=]"
	@echo "  frontend-vendor      Rebuild the browser prover and its reference points."
	@echo "  subject              Print a profile's subject line: CONTROLLER= CHAIN_ID= REGISTRY=."
	@echo "  prove                Prove an email: EML= SALT= CONTROLLER= CHAIN_ID= REGISTRY=."
	@echo "  vectors              Regenerate the proof vectors the contract tests load."
	@echo "  key-hash             Hash a DKIM key for management: SELECTOR=<s>."
	@echo "  demo-anvil           Start a local chain at the fixture emails' time."
	@echo "  demo-deploy          Deploy a demo Registry onto the local chain."
	@echo "  demo-deploy-chain    Deploy a demo Registry elsewhere: DEMO_RPC_URL= DEMO_PRIVATE_KEY=."
	@echo "  e2e                  Drive the frontend end to end in headless Chromium."
	@echo ""
	@echo "  deploy-verifier-dry  Simulate the verifier pair deployment."
	@echo "  deploy-verifier      Deploy the immutable email verifier pair."
	@echo ""
	@echo "  deploy-dry   Simulate the Registry deployment without broadcasting."
	@echo "  deploy       Deploy the Registry via CreateX, then verify it."
	@echo "  verify       Re-verify the deployed verifier stack and Registry."
	@echo "  help         Show this help message."
	@echo ""
	@echo "Deployment workflow:"
	@echo "  # Set in .env (copy .env.example and fill in):"
	@echo "  #   RPC_URL, DEPLOYER_PRIVATE_KEY, SALT, EXPECTED_ADDRESS,"
	@echo "  #   HONK_VERIFIER_SALT/_EXPECTED_ADDRESS, VERIFIER_SALT/"
	@echo "  #   _EXPECTED_ADDRESS, VERIFIER, MANAGEMENT, ETHERSCAN_API_KEY,"
	@echo "  #   and, after deploy-verifier, RELATIONS_LIB, ZK_TRANSCRIPT_LIB"
	@echo "  # Project-pinned defaults in .env.maintainer (committed):"
	@echo "  #   DOMAIN, CREATEX"
	@echo "  make deploy-verifier  # Deploy the immutable verifier pair first."
	@echo "  make deploy-dry  # Simulate; verifies the CreateX address matches."
	@echo "  make deploy      # Broadcast the deployment and verify the source."
	@echo "  make verify      # Re-verify if explorer verification lagged."
	@echo ""

.DEFAULT_GOAL := help
