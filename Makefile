# [DAN] ARRAY — developer & CI entry points. Zero runtime dependencies; every target is Node
# stdlib only. All test invocations pin --test-concurrency=1: the suites bind real sockets on
# fixed ports, so running the test files in parallel would let their listeners steal each other's
# packets. Run `make help` for the list.

NODE ?= node
TEST_RUNNER = $(NODE) --test --test-concurrency=1

# Existing adversarial/security suites only (a subset of the full suite): tampered-ciphertext and
# wrong-passphrase rejection, oversized-frame rejection, cross-origin 403, DNS-rebind 403, and
# garbage-datagram rejection.
ATTACK_TESTS = test/crypto.test.mjs test/handshake.test.mjs test/server.test.mjs test/discovery.test.mjs

.DEFAULT_GOAL := help

.PHONY: help test attack demo bench

help: ## Show this help
	@echo "[DAN] ARRAY — make targets:"
	@echo
	@echo "  make test     Run the full test suite (node --test --test-concurrency=1 test/*.test.mjs)"
	@echo "  make attack   Run only the adversarial/security suites and prove they reject"
	@echo "  make demo     Reproducible crypto-core demo — seal/open, plus wrong-passphrase & tamper failures"
	@echo "  make bench    Crypto throughput — scrypt KDF time and AES-256-GCM seal/open (ops/sec, MB/s)"
	@echo "  make help     Show this help"
	@echo
	@echo "  No LAN and no dependencies are required for demo or bench. Node stdlib only."

test: ## Run the full test suite
	$(TEST_RUNNER) test/*.test.mjs

attack: ## Run only the adversarial/security suites
	@echo "── [DAN] ARRAY: adversarial suites ────────────────────────────────────────────"
	@echo "Proving the attacks are rejected: tampered-ciphertext, wrong-passphrase,"
	@echo "oversized-frame, cross-origin 403, DNS-rebind 403, garbage-datagram."
	@echo "────────────────────────────────────────────────────────────────────────────────"
	$(TEST_RUNNER) $(ATTACK_TESTS)

demo: ## Reproducible crypto-core demo (no LAN needed)
	$(NODE) scripts/demo.mjs

bench: ## Crypto throughput benchmark (no LAN needed, < ~15s)
	$(NODE) scripts/bench.mjs
