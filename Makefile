PY ?= python

.PHONY: test cov lint sample bench clean

test:
	$(PY) -m pytest tests

cov:
	$(PY) -m pytest tests --cov=mcp_guard --cov-report=html
	@echo "open htmlcov/index.html"

# Regenerate the README sample from a real run so it cannot drift.
sample:
	$(PY) -m mcp_guard.cli tests/fixtures/vulnerable-server \
	    --allow-execute --skip-install --offline \
	    > docs/sample-output.txt 2>/dev/null || true
	@echo "wrote docs/sample-output.txt"

# Regenerate the measured precision/recall table.
bench:
	$(PY) scripts/benchmark.py > docs/fixture-benchmark.txt 2>/dev/null || true
	@echo "wrote docs/fixture-benchmark.txt"

clean:
	rm -rf .pytest_cache htmlcov .coverage
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

golden:
	$(PY) scripts/golden.py
	@echo "regenerated tests/golden/ -- justify every delta in the commit"

profile:
	$(PY) scripts/profile.py > docs/profile-baseline.md
	@echo "wrote docs/profile-baseline.md"
