# PHP2SHELL — development tasks
#
# Everything runs on the standard library. There is no install step, and
# `make test` must work on a clean checkout with nothing but python3.

PYTHON ?= python3
SCANNER := scanner
EXPLOIT := exploit-kit

.PHONY: help test test-scanner test-exploit lint compile clean scan-help exploit-help

help:
	@echo "make test          run the full unit suite (scanner)"
	@echo "make test-scanner  scanner tests only"
	@echo "make test-exploit  exploit-kit import + selftest sanity"
	@echo "make compile       byte-compile every module to catch syntax errors"
	@echo "make lint          check for stray tabs / trailing whitespace"
	@echo "make clean         remove caches and build artefacts"
	@echo "make scan-help     print scanner usage"
	@echo "make exploit-help  print exploit-kit usage"

test: test-scanner test-exploit

test-scanner:
	cd $(SCANNER) && $(PYTHON) -m unittest discover -s tests -v

test-exploit:
	cd $(EXPLOIT) && $(PYTHON) -m compileall -q php2shell_exploit && \
		$(PYTHON) -c "import php2shell_exploit as m; print('php2shell_exploit', m.__version__)"

compile:
	$(PYTHON) -m compileall -q $(SCANNER)/php2shell $(EXPLOIT)/php2shell_exploit

lint:
	@! grep -rnP '\t' --include='*.py' $(SCANNER) $(EXPLOIT) || \
		(echo "error: tab characters in python sources"; exit 1)
	@! grep -rn ' $' --include='*.py' $(SCANNER) $(EXPLOIT) || \
		(echo "error: trailing whitespace"; exit 1)

scan-help:
	cd $(SCANNER) && $(PYTHON) ./scan --help

exploit-help:
	cd $(EXPLOIT) && $(PYTHON) ./exploit --help

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
	rm -rf build dist *.egg-info .pytest_cache .coverage
