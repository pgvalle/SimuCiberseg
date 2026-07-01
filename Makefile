VENV = .pyenv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

RUNS ?= 5
EXP ?= all

.PHONY: all setup run run plot plot clean

all: setup run

setup:
	python3 -m venv $(VENV)
	$(PIP) install matplotlib scapy numpy scipy

# --- Run Simulation Targets ---
run:
	$(PYTHON) run.py -e $(EXP) -r $(RUNS)

# --- Plot-Only Targets ---
plot:
	$(PYTHON) run.py --plot-only -e $(EXP)

clean:
	rm -rf out sims/p4app.json
