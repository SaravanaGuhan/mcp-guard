PY ?= python
SAMPLE := docs/generated/sample-output.txt

.PHONY: install test cov lint sample bench golden profile clean

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest tests

lint:
	$(PY) -m ruff check src tests scripts

cov:
	$(PY) -m pytest tests --cov=mcp_guard --cov-report=html
	@echo "open htmlcov/index.html"

# Regenerate the README sample from a real run so it cannot drift.
sample:
	@$(PY) -c "import io,sys; io.open(sys.argv[1],'w',encoding='utf-8',newline=chr(10)).write(open(sys.argv[2],encoding='utf-8').read())" $(SAMPLE) docs/generated/sample-output.header
	$(PY) -m mcp_guard.cli tests/fixtures/vulnerable-server \
	    --allow-execute --skip-install --offline --quiet \
	    >> $(SAMPLE) 2>/dev/null || true
	@echo "wrote $(SAMPLE)"

# Regenerate the measured precision/recall table.
bench:
	$(PY) scripts/benchmark.py > docs/generated/fixture-benchmark.txt 2>/dev/null || true
	@echo "wrote docs/generated/fixture-benchmark.txt"

clean:
	rm -rf .pytest_cache htmlcov .coverage
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

golden:
	$(PY) scripts/golden.py
	@echo "regenerated tests/golden/ -- justify every delta in the commit"

profile:
	$(PY) scripts/profile.py > docs/profile-baseline.md
	@echo "wrote docs/profile-baseline.md"
