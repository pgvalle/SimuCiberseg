#!/usr/bin/env python3
import os
import shutil
import subprocess

# Ensure directory structures are set up
os.makedirs("out/no_backlog", exist_ok=True)
os.makedirs("out/backlog", exist_ok=True)

experiments = [
    ("base", "sims/base.json"),
    ("ext", "sims/ext.json"),
    ("ext_v6", "sims/ext-v6.json"),
]

runs = 5


def run_sim(config_path, log_dir, env_extra=None):
    shutil.copy(config_path, "sims/p4app.json")
    os.makedirs(log_dir, exist_ok=True)

    env = os.environ.copy()
    env["P4APP_LOGDIR"] = log_dir
    if env_extra:
        env.update(env_extra)

    print(f"Running: {config_path} -> {log_dir} (env: {env_extra})")
    res = subprocess.run(
        ["./p4app/p4app", "run", "sims"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if res.returncode != 0:
        print(f"ERROR: run failed for {config_path} -> {log_dir}")
        print(f"STDOUT:\n{res.stdout.decode()[-1000:]}")
        print(f"STDERR:\n{res.stderr.decode()[-1000:]}")
    return res.returncode == 0


# Total progress tracker
total_steps = len(experiments) * runs * 2  # mixed_no_backlog, mixed_backlog
current_step = 0

print(f"Starting experimental suite with {runs} runs of 90s simulations.")
print(f"Total steps to execute: {total_steps}")

for exp_name, config_path in experiments:
    for r in range(1, runs + 1):
        # 1. Run Mixed 0.1 no_backlog model
        current_step += 1
        print(
            f"\n[Step {current_step}/{total_steps}] Mixed 0.1 (no_backlog) for {exp_name} run {r}..."
        )
        run_sim(
            config_path,
            f"./out/no_backlog/{exp_name}/run_{r}",
            {"ATTACK_MODEL": "no_backlog"},
        )

        # 2. Run Mixed 0.1 Backlog model
        current_step += 1
        print(
            f"\n[Step {current_step}/{total_steps}] (Backlog) for {exp_name} run {r}..."
        )
        run_sim(
            config_path,
            f"./out/backlog/{exp_name}/run_{r}",
            {"ATTACK_MODEL": "backlog"},
        )

print("\n================ All Simulations Finished ================")
print("Generating no_backlog plots...")
subprocess.run(
    [".pyenv/bin/python", "plot_results.py"],
    env={"OUT_DIR": "out/no_backlog", "PYTHONPATH": "."},
)
print("Generating Backlog plots...")
subprocess.run(
    [".pyenv/bin/python", "plot_results.py"],
    env={"OUT_DIR": "out/backlog", "PYTHONPATH": "."},
)
print("Plots generated successfully under out/no_backlog/ and out/backlog/.")
