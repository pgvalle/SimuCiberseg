import os
import sys
from pathlib import Path

import numpy as np
import scipy.stats as st

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from scapy.all import IP, TCP, IPv6
except ImportError:
    print("Please install matplotlib, scapy, numpy, scipy")
    sys.exit(1)


EXPERIMENTS = [
    ("v4_base", "P4Drop"),
    ("v4_ext", "P4DropExt IPv4"),
    ("v6_ext", "P4DropExt IPv6"),
]
MIXED_RATIOS = ["0.0", "0.1", "0.2", "0.5"]
ATTACK_RATIOS = ["0.1", "0.2", "0.5"]
SENT_PCAP = ("s1-eth2", "out")
RECV_PCAP = ("s1-eth1", "in")


def find_pcap(base_dir, iface_prefix, suffix):
    pcap = Path(base_dir) / f"{iface_prefix}_{suffix}.pcap"
    return str(pcap) if pcap.exists() else None


def legit_ip_for(exp_name):
    if exp_name == "v6_ext":
        return "2001:db8:2::101"
    return "10.0.2.101"


def tcp_src_and_payload_len(packet, is_v6=False):
    if is_v6:
        if IPv6 in packet and TCP in packet:
            return packet[IPv6].src, len(bytes(packet[TCP].payload))
    elif IP in packet and TCP in packet:
        return packet[IP].src, len(bytes(packet[TCP].payload))
    return None, 0


def iter_runs(exp_name):
    exp_dir = Path("out") / exp_name
    if not exp_dir.exists():
        return []
    return sorted(d.name for d in exp_dir.iterdir() if d.is_dir() and d.name.startswith("run_"))


def count_payload_packets(pcap_path, exp_name, legit_ip):
    from scapy.all import PcapReader

    is_v6 = exp_name == "v6_ext"
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


def analyze_run(exp_name, scenario):
    log_dir = Path("out") / exp_name / scenario
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


def collect_metric(exp_name, scenario, metric_name):
    values = []
    for run in iter_runs(exp_name):
        counts = analyze_run(exp_name, f"{run}/{scenario}")
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


def available_experiments():
    return [(name, label) for name, label in EXPERIMENTS if Path("out", name).exists()]


def save_validation_plot(experiments):
    labels = [label for _, label in experiments]
    x = np.arange(len(labels))
    width = 0.36

    legit_means = []
    legit_errs = []
    spoof_means = []
    spoof_errs = []

    for exp_name, _ in experiments:
        mean, err = mean_and_sem(collect_metric(exp_name, "legit", "ldr"))
        legit_means.append(mean)
        legit_errs.append(err)

        mean, err = mean_and_sem(collect_metric(exp_name, "spoof", "alr"))
        spoof_means.append(mean)
        spoof_errs.append(err)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5), sharey=True)

    axes[0].bar(x, legit_means, width, yerr=legit_errs, color="#2e7d32", capsize=4)
    axes[0].set_title("Entrega de Trafego Legitimo")
    axes[0].set_ylabel("Pacotes recebidos / transmitidos (%)")
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(labels, rotation=15, ha="right")
    axes[0].set_ylim(0, 105)
    axes[0].grid(axis="y", alpha=0.25)

    axes[1].bar(x, spoof_means, width, yerr=spoof_errs, color="#c62828", capsize=4)
    axes[1].set_title("Vazamento de Ataque Spoofado")
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(labels, rotation=15, ha="right")
    axes[1].set_ylim(0, 105)
    axes[1].grid(axis="y", alpha=0.25)

    fig.suptitle("Validacao Basica das Implementacoes")
    fig.tight_layout()
    fig.savefig("out/validation_correctness.png")
    plt.close(fig)


def collect_mixed_series(exp_name, ratios, metric_name):
    means = []
    errs = []

    for ratio in ratios:
        values = collect_metric(exp_name, f"mixed_{ratio}", metric_name)
        mean, err = mean_and_sem(values)
        means.append(mean)
        errs.append(err)

        if not values:
            print(f"Warning: missing data for {exp_name}/mixed_{ratio}")

    return np.array(means), np.array(errs)


def save_mixed_plot(experiments, ratios, metric_name, ylabel, title, output_file):
    x = np.array([float(r) * 100.0 for r in ratios])

    plt.figure(figsize=(8, 4.8))
    for exp_name, label in experiments:
        means, errs = collect_mixed_series(exp_name, ratios, metric_name)
        valid = ~np.isnan(means)
        if not np.any(valid):
            continue
        plt.errorbar(
            x[valid],
            means[valid],
            yerr=errs[valid],
            marker="o",
            capsize=4,
            label=label,
        )

    plt.xlabel("Razao de Fluxos de Ataque (%)")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.ylim(-5, 105)
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()


def main():
    experiments = available_experiments()
    if not experiments:
        print("No experiment outputs found in out/.")
        return

    save_validation_plot(experiments)
    save_mixed_plot(
        experiments,
        MIXED_RATIOS,
        "ldr",
        "Entrega legitima (%)",
        "Entrega de Trafego Legitimo em Cenario Misto",
        "out/mixed_legitimate_delivery.png",
    )
    save_mixed_plot(
        experiments,
        ATTACK_RATIOS,
        "alr",
        "Vazamento de ataque (%)",
        "Vazamento de Ataque em Cenario Misto",
        "out/mixed_attack_leakage.png",
    )

    print("Plots saved in out/ directory.")


if __name__ == "__main__":
    main()
