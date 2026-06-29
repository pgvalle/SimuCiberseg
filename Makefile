VENV = .pyenv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

RUNS ?= 3
RATIOS = 0.0 0.1 0.2 0.5

.PHONY: all setup v4_base v4_ext v6_ext plot clean

all: setup v4_base v4_ext v6_ext plot

setup:
	python3 -m venv $(VENV)
	$(PIP) install matplotlib scapy numpy scipy

v4_base:
	@echo "Running v4_base experiments for $(RUNS) runs..."
	@for i in $$(seq 1 $(RUNS)); do \
		echo "=== v4_base Run $$i / $(RUNS) ==="; \
		mkdir -p out/v4_base/run_$$i/spoof; \
		cp sims/base-spoof.json sims/p4app.json; \
		P4APP_LOGDIR=./out/v4_base/run_$$i/spoof ./p4app/p4app run sims; \
		mkdir -p out/v4_base/run_$$i/legit; \
		cp sims/base-legit.json sims/p4app.json; \
		P4APP_LOGDIR=./out/v4_base/run_$$i/legit ./p4app/p4app run sims; \
		for ratio in $(RATIOS); do \
			mkdir -p out/v4_base/run_$$i/mixed_$$ratio; \
			sed "s/__RATIO__/$$ratio/g" sims/base-mixed.json > sims/p4app.json; \
			P4APP_LOGDIR=./out/v4_base/run_$$i/mixed_$$ratio ./p4app/p4app run sims; \
		done \
	done

v4_ext:
	@echo "Running v4_ext experiments for $(RUNS) runs..."
	@for i in $$(seq 1 $(RUNS)); do \
		echo "=== v4_ext Run $$i / $(RUNS) ==="; \
		mkdir -p out/v4_ext/run_$$i/spoof; \
		cp sims/ext-spoof.json sims/p4app.json; \
		P4APP_LOGDIR=./out/v4_ext/run_$$i/spoof ./p4app/p4app run sims; \
		mkdir -p out/v4_ext/run_$$i/legit; \
		cp sims/ext-legit.json sims/p4app.json; \
		P4APP_LOGDIR=./out/v4_ext/run_$$i/legit ./p4app/p4app run sims; \
		for ratio in $(RATIOS); do \
			mkdir -p out/v4_ext/run_$$i/mixed_$$ratio; \
			sed "s/__RATIO__/$$ratio/g" sims/ext-mixed.json > sims/p4app.json; \
			P4APP_LOGDIR=./out/v4_ext/run_$$i/mixed_$$ratio ./p4app/p4app run sims; \
		done \
	done

v6_ext:
	@echo "Running v6_ext experiments for $(RUNS) runs..."
	@for i in $$(seq 1 $(RUNS)); do \
		echo "=== v6_ext Run $$i / $(RUNS) ==="; \
		mkdir -p out/v6_ext/run_$$i/spoof; \
		cp sims/ext-v6-spoof.json sims/p4app.json; \
		P4APP_LOGDIR=./out/v6_ext/run_$$i/spoof ./p4app/p4app run sims; \
		mkdir -p out/v6_ext/run_$$i/legit; \
		cp sims/ext-v6-legit.json sims/p4app.json; \
		P4APP_LOGDIR=./out/v6_ext/run_$$i/legit ./p4app/p4app run sims; \
		for ratio in $(RATIOS); do \
			mkdir -p out/v6_ext/run_$$i/mixed_$$ratio; \
			sed "s/__RATIO__/$$ratio/g" sims/ext-v6-mixed.json > sims/p4app.json; \
			P4APP_LOGDIR=./out/v6_ext/run_$$i/mixed_$$ratio ./p4app/p4app run sims; \
		done \
	done

plot:
	$(PYTHON) plot_results.py

clean:
	rm -rf out p4drop_experiments_performance.png sims/p4app.json
