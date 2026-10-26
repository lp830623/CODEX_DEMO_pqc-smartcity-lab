# liboqs-python loads the shared library from OQS_INSTALL_PATH.
# Override this if you installed liboqs somewhere else.
export OQS_INSTALL_PATH ?= /opt/liboqs
export LD_LIBRARY_PATH := $(OQS_INSTALL_PATH)/lib:$(LD_LIBRARY_PATH)

PY ?= python

.PHONY: install test bench charts demo mqtt provision

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest

bench:
	$(PY) -m pqc_smartcity bench --iterations 80 --warmup 10 --output results
	$(PY) -m pqc_smartcity charts --results results

charts:
	$(PY) -m pqc_smartcity charts --results results

demo:
	$(PY) -m pqc_smartcity demo --messages 2

provision:
	$(PY) -m pqc_smartcity provision

mqtt:
	docker compose up --build
