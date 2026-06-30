VENV = .pyenv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

RUNS ?= 5
EXP ?= all

.PHONY: all setup run run-base run-ext run-ext-v6 plot plot-base plot-ext plot-ext-v6 clean

all: setup run

setup:
	python3 -m venv $(VENV)
	$(PIP) install matplotlib scapy numpy scipy

# --- Run Simulation Targets ---
run:
	$(PYTHON) run.py -r $(RUNS)

run-exp:
	$(PYTHON) run.py -e $(ALL) -r $(RUNS)

# --- Plot-Only Targets ---
plot:
	$(PYTHON) run.py --plot-only

plot-base:
$(PYTHON) run.py --plot-only -e $(EXP)

clean:
	rm -rf out sims/p4app.json
