import os
import sys
from collections import defaultdict
from pathlib import Path

OUT_DIR = os.environ.get("OUT_DIR", "out")

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
    ("base", "P4Drop"),
    ("ext", "P4DropExt IPv4"),
    ("ext_v6", "P4DropExt IPv6"),
]
MIXED_RATIOS = ["0.0", "0.1", "0.2", "0.5"]
ATTACK_RATIOS = ["0.1", "0.2", "0.5"]
SENT_PCAP = ("s1-eth2", "out")
RECV_PCAP = ("s1-eth1", "in")


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


def iter_runs(exp_name):
    exp_dir = Path(OUT_DIR) / exp_name
    if not exp_dir.exists():
        return []
    return sorted(
        d.name for d in exp_dir.iterdir() if d.is_dir() and d.name.startswith("run_")
    )


def count_payload_packets(pcap_path, exp_name, legit_ip):
    from scapy.all import PcapReader

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


def analyze_run(exp_name, run):
    log_dir = Path(OUT_DIR) / exp_name / run
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


def collect_metric(exp_name, metric_name):
    values = []
    for run in iter_runs(exp_name):
        counts = analyze_run(exp_name, run)
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
    return [(name, label) for name, label in EXPERIMENTS if Path(OUT_DIR, name).exists()]


def save_validation_plot(experiments):
    labels = [label for _, label in experiments]
    x = np.arange(len(labels))
    width = 0.36

    legit_means = []
    legit_errs = []
    spoof_means = []
    spoof_errs = []

    for exp_name, _ in experiments:
        mean, err = mean_and_sem(collect_metric(exp_name, "ldr"))
        legit_means.append(mean)
        legit_errs.append(err)

        mean, err = mean_and_sem(collect_metric(exp_name, "alr"))
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

    title_suffix = " (com backlog)" if "backlog" in OUT_DIR.lower() else " (sem backlog)"
    fig.suptitle(f"Desempenho no Cenário Misto{title_suffix}")
    fig.tight_layout()
    fig.savefig(f"{OUT_DIR}/validation_correctness.png")
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


# ---------------------------------------------------------------------------
# Flow block speed comparison
# ---------------------------------------------------------------------------

MAX_BLOCK_SPEED_INDEX = 150


def get_flow_delivery_profiles(sent_pcap, recv_pcap, legit_ip, is_v6=False):
    """Return lists of bools indicating if k-th packet of each flow was delivered."""
    from scapy.all import PcapReader

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


def save_flow_block_speed_plot(experiments):
    """Average flow delivery profiles over runs, and plot flow block speed."""
    fig, ax = plt.subplots(figsize=(7.5, 4.8))

    colors = {"base": "blue", "ext": "orange", "ext_v6": "green"}

    for exp_name, label in experiments:
        all_profiles = []
        for run in iter_runs(exp_name):
            log_dir = Path(OUT_DIR) / exp_name / run
            sent_pcap = find_pcap(log_dir, *SENT_PCAP)
            recv_pcap = find_pcap(log_dir, *RECV_PCAP)
            if not sent_pcap or not recv_pcap:
                continue

            legit_ip = legit_ip_for(exp_name)
            is_v6 = exp_name == "ext_v6"

            profiles = get_flow_delivery_profiles(
                sent_pcap, recv_pcap, legit_ip, is_v6
            )
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
            alpha=0.15
        )

    title_suffix = " (com backlog)" if "backlog" in OUT_DIR.lower() else " (sem backlog)"
    ax.set_title(f"Taxa de entrega de pacotes nos fluxos de ataque{title_suffix}")
    ax.set_xlabel("Índice do pacote no fluxo (seq. cronológica)")
    ax.set_ylabel("Probabilidade de entrega (%)")
    ax.set_ylim(-5, 105)
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(f"{OUT_DIR}/flow_block_speed.png")
    plt.close(fig)
    print(f"Saved {OUT_DIR}/flow_block_speed.png")


def main():
    experiments = available_experiments()
    if not experiments:
        print(f"No experiment outputs found in {OUT_DIR}/.")
        return

    save_validation_plot(experiments)
    save_flow_block_speed_plot(experiments)
    print(f"Plots saved in {OUT_DIR}/ directory.")


if __name__ == "__main__":
    main()
