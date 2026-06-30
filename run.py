#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import scipy.stats as st

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from scapy.all import IP, TCP, IPv6, PcapReader
except ImportError:
    print("Please install matplotlib, scapy, numpy, scipy")
    sys.exit(1)

EXPERIMENTS = [
    ("base", "P4Drop"),
    ("ext", "P4DropExt IPv4"),
    ("ext_v6", "P4DropExt IPv6"),
]
SENT_PCAP = ("s1-eth2", "out")
RECV_PCAP = ("s1-eth1", "in")

MAX_BLOCK_SPEED_INDEX = 150


def find_pcap(base_dir, iface_prefix, suffix):
    pcap = Path(base_dir) / f"{iface_prefix}_{suffix}.pcap"
    return str(pcap) if pcap.exists() else None


def legit_ip_for(exp_name):
    if exp_name == "ext_v6":
        return "2001:db8:2::101"
    return "10.0.2.101"


def tcp_src_and_payload_len(packet, is_v6=False):
    if is_v6:
        if IPv6 in packet and TCP in packet:
            return packet[IPv6].src, len(bytes(packet[TCP].payload))
    elif IP in packet and TCP in packet:
        return packet[IP].src, len(bytes(packet[TCP].payload))
    return None, 0


def iter_runs(out_dir, exp_name):
    exp_dir = Path(out_dir) / exp_name
    if not exp_dir.exists():
        return []
    return sorted(
        d.name for d in exp_dir.iterdir() if d.is_dir() and d.name.startswith("run_")
    )


def count_payload_packets(pcap_path, exp_name, legit_ip):
    is_v6 = exp_name == "ext_v6"
    legit = 0
    attack = 0

    try:
        with PcapReader(pcap_path) as reader:
            for packet in reader:
                src, payload_len = tcp_src_and_payload_len(packet, is_v6=is_v6)
                if src is None or payload_len == 0:
                    continue
                if src == legit_ip:
                    legit += 1
                else:
                    attack += 1
    except Exception as exc:
        print(f"Warning: failed reading {pcap_path}: {exc}")

    return legit, attack


def analyze_run(out_dir, exp_name, run):
    log_dir = Path(out_dir) / exp_name / run
    sent_pcap = find_pcap(log_dir, *SENT_PCAP)
    recv_pcap = find_pcap(log_dir, *RECV_PCAP)

    if not sent_pcap or not recv_pcap:
        return None

    legit_ip = legit_ip_for(exp_name)
    legit_sent, attack_sent = count_payload_packets(sent_pcap, exp_name, legit_ip)
    legit_recv, attack_recv = count_payload_packets(recv_pcap, exp_name, legit_ip)

    return {
        "legit_sent": legit_sent,
        "legit_recv": legit_recv,
        "attack_sent": attack_sent,
        "attack_recv": attack_recv,
    }


def metric_rates(counts):
    if counts is None:
        return np.nan, np.nan

    ldr = np.nan
    alr = np.nan

    if counts["legit_sent"] > 0:
        ldr = counts["legit_recv"] / counts["legit_sent"] * 100.0
    if counts["attack_sent"] > 0:
        alr = counts["attack_recv"] / counts["attack_sent"] * 100.0

    return ldr, alr


def collect_metric(out_dir, exp_name, metric_name):
    values = []
    for run in iter_runs(out_dir, exp_name):
        counts = analyze_run(out_dir, exp_name, run)
        ldr, alr = metric_rates(counts)
        value = ldr if metric_name == "ldr" else alr
        if not np.isnan(value):
            values.append(value)
    return values


def mean_and_sem(values):
    if not values:
        return np.nan, 0.0
    if len(values) == 1:
        return float(values[0]), 0.0
    return float(np.mean(values)), float(st.sem(values))


def available_experiments(out_dir):
    return [
        (name, label) for name, label in EXPERIMENTS if Path(out_dir, name).exists()
    ]


def save_validation_plot(out_dir, experiments):
    labels = [label for _, label in experiments]
    x = np.arange(len(labels))
    width = 0.36

    legit_means = []
    legit_errs = []
    spoof_means = []
    spoof_errs = []

    for exp_name, _ in experiments:
        mean, err = mean_and_sem(collect_metric(out_dir, exp_name, "ldr"))
        legit_means.append(mean)
        legit_errs.append(err)

        mean, err = mean_and_sem(collect_metric(out_dir, exp_name, "alr"))
        spoof_means.append(mean)
        spoof_errs.append(err)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5), sharey=True)

    axes[0].bar(x, legit_means, width, yerr=legit_errs, color="#2e7d32", capsize=4)
    axes[0].set_title("Entrega de Tráfego Legítimo")
    axes[0].set_ylabel("Pacotes recebidos / transmitidos (%)")
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(labels, rotation=15, ha="right")
    axes[0].set_ylim(0, 105)
    axes[0].grid(axis="y", alpha=0.25)

    axes[1].bar(x, spoof_means, width, yerr=spoof_errs, color="#c62828", capsize=4)
    axes[1].set_title("Vazamento de Tráfego Malicioso")
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(labels, rotation=15, ha="right")
    axes[1].set_ylim(0, 105)
    axes[1].grid(axis="y", alpha=0.25)

    title_suffix = (
        " (com backlog)" if "backlog" in out_dir.lower() else " (sem backlog)"
    )
    fig.suptitle(f"Desempenho no Cenário Misto{title_suffix}")
    fig.tight_layout()
    fig.savefig(f"{out_dir}/validation_correctness.png")
    plt.close(fig)


def get_flow_delivery_profiles(sent_pcap, recv_pcap, legit_ip, is_v6=False):
    """Return lists of bools indicating if k-th packet of each flow was delivered."""
    sent_flows = defaultdict(list)
    try:
        with PcapReader(sent_pcap) as reader:
            for pkt in reader:
                if is_v6:
                    if IPv6 not in pkt or TCP not in pkt:
                        continue
                    src = pkt[IPv6].src
                else:
                    if IP not in pkt or TCP not in pkt:
                        continue
                    src = pkt[IP].src

                if len(bytes(pkt[TCP].payload)) == 0:
                    continue
                if src == legit_ip:
                    continue

                flow_key = (src, pkt[TCP].sport)
                sent_flows[flow_key].append(pkt[TCP].seq)
    except Exception as exc:
        print(f"Warning: failed reading {sent_pcap}: {exc}")
        return []

    recv_counts = defaultdict(int)
    try:
        with PcapReader(recv_pcap) as reader:
            for pkt in reader:
                if is_v6:
                    if IPv6 not in pkt or TCP not in pkt:
                        continue
                    src = pkt[IPv6].src
                else:
                    if IP not in pkt or TCP not in pkt:
                        continue
                    src = pkt[IP].src

                if len(bytes(pkt[TCP].payload)) == 0:
                    continue
                if src == legit_ip:
                    continue

                flow_key = (src, pkt[TCP].sport)
                recv_counts[(flow_key, pkt[TCP].seq)] += 1
    except Exception as exc:
        print(f"Warning: failed reading {recv_pcap}: {exc}")
        return []

    profiles = []
    for flow_key, seqs in sent_flows.items():
        profile = []
        for seq in seqs[:MAX_BLOCK_SPEED_INDEX]:
            count_key = (flow_key, seq)
            if recv_counts[count_key] > 0:
                profile.append(True)
                recv_counts[count_key] -= 1
            else:
                profile.append(False)
        if len(profile) < MAX_BLOCK_SPEED_INDEX:
            profile += [False] * (MAX_BLOCK_SPEED_INDEX - len(profile))
        profiles.append(profile)

    return profiles


def save_flow_block_speed_plot(out_dir, experiments):
    """Average flow delivery profiles over runs, and plot flow block speed."""
    fig, ax = plt.subplots(figsize=(7.5, 4.8))

    colors = {"base": "blue", "ext": "orange", "ext_v6": "green"}

    for exp_name, label in experiments:
        all_profiles = []
        for run in iter_runs(out_dir, exp_name):
            log_dir = Path(out_dir) / exp_name / run
            sent_pcap = find_pcap(log_dir, *SENT_PCAP)
            recv_pcap = find_pcap(log_dir, *RECV_PCAP)
            if not sent_pcap or not recv_pcap:
                continue

            legit_ip = legit_ip_for(exp_name)
            is_v6 = exp_name == "ext_v6"

            profiles = get_flow_delivery_profiles(sent_pcap, recv_pcap, legit_ip, is_v6)
            all_profiles.extend(profiles)

        if not all_profiles:
            continue

        profiles_arr = np.array(all_profiles)
        delivery_rate = np.mean(profiles_arr, axis=0) * 100.0
        sem = st.sem(profiles_arr, axis=0) * 100.0
        indices = np.arange(1, MAX_BLOCK_SPEED_INDEX + 1)
        color = colors.get(exp_name, None)

        ax.plot(indices, delivery_rate, label=label, color=color, linewidth=2)
        # Add shaded band representing the Standard Error of the Mean (SEM)
        ax.fill_between(
            indices,
            np.clip(delivery_rate - sem, 0, 100),
            np.clip(delivery_rate + sem, 0, 100),
            color=color,
            alpha=0.15,
        )

    title_suffix = (
        " (com backlog)" if "backlog" in out_dir.lower() else " (sem backlog)"
    )
    ax.set_title(f"Taxa de entrega de pacotes nos fluxos de ataque{title_suffix}")
    ax.set_xlabel("Índice do pacote no fluxo (seq. cronológica)")
    ax.set_ylabel("Probabilidade de entrega (%)")
    ax.set_ylim(-5, 105)
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(f"{out_dir}/flow_block_speed.png")
    plt.close(fig)
    print(f"Saved {out_dir}/flow_block_speed.png")


def generate_plots(out_dir, experiment_filter="all"):
    experiments = available_experiments(out_dir)
    if experiment_filter != "all":
        experiments = [e for e in experiments if e[0] == experiment_filter]

    if not experiments:
        print(
            f"No experiment outputs found in {out_dir}/ for filter '{experiment_filter}'."
        )
        return

    save_validation_plot(out_dir, experiments)
    save_flow_block_speed_plot(out_dir, experiments)
    print(f"Plots saved in {out_dir}/ directory.")


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


def main():
    parser = argparse.ArgumentParser(
        description="Run simulation experiments and generate plots."
    )
    parser.add_argument(
        "-e",
        "--experiment",
        choices=["all", "base", "ext", "ext_v6"],
        default="all",
        help="Select a specific experiment to run (default: all)",
    )
    parser.add_argument(
        "-p",
        "--plot-only",
        action="store_true",
        help="Skip simulations and only generate/regenerate plots",
    )
    parser.add_argument(
        "-r",
        "--runs",
        type=int,
        default=5,
        help="Number of simulation runs (default: 5)",
    )
    args = parser.parse_args()

    # Filter experiments
    if args.experiment == "all":
        experiments_to_run = EXPERIMENTS
    else:
        experiments_to_run = [e for e in EXPERIMENTS if e[0] == args.experiment]

    if not args.plot_only:
        # Ensure output directories are clean
        os.makedirs("out/no_backlog", exist_ok=True)
        os.makedirs("out/backlog", exist_ok=True)

        # Total progress tracker
        total_steps = len(experiments_to_run) * args.runs * 2  # no_backlog, backlog
        current_step = 0

        print(f"Starting experimental suite with {args.runs} runs of 90s simulations.")
        print(f"Total steps to execute: {total_steps}")

        for exp_name, config_path in experiments_to_run:
            for r in range(1, args.runs + 1):
                # 1. Run attack with no_backlog model
                current_step += 1
                print(
                    f"\n[Step {current_step}/{total_steps}] (no_backlog) for {exp_name} run {r}..."
                )
                run_sim(
                    config_path,
                    f"./out/no_backlog/{exp_name}/run_{r}",
                    {"ATTACK_MODEL": "no_backlog"},
                )

                # 2. Run attack with backlog model
                current_step += 1
                print(
                    f"\n[Step {current_step}/{total_steps}] (backlog) for {exp_name} run {r}..."
                )
                run_sim(
                    config_path,
                    f"./out/backlog/{exp_name}/run_{r}",
                    {"ATTACK_MODEL": "backlog"},
                )

        print("\n================ All Simulations Finished ================")

    print("Generating no_backlog plots...")
    generate_plots("out/no_backlog", args.experiment)

    print("Generating backlog plots...")
    generate_plots("out/backlog", args.experiment)

    print("Plots generated successfully under out/no_backlog/ and out/backlog/.")


if __name__ == "__main__":
    main()
