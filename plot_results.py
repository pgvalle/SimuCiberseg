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


MIXED_RATIOS = ["0.1", "0.2", "0.5"]
MAX_TIME = 120
SENT_IFACE = "s1-eth2"
RECV_IFACE = "s1-eth1"


def find_pcap(base_dir, iface_prefix, suffix):
    pcap = Path(base_dir) / f"{iface_prefix}_{suffix}.pcap"
    return str(pcap) if pcap.exists() else None


def legit_ip_for(exp_name=None, is_v6=False):
    if is_v6 or exp_name == "v6_ext":
        return "2001:db8:2::101"
    return "10.0.2.101"


def tcp_source(packet, is_v6=False):
    if is_v6:
        if IPv6 in packet and TCP in packet:
            return packet[IPv6].src
    elif IP in packet and TCP in packet:
        return packet[IP].src
    return None


def analyze_mixed_run(log_dir, is_v6=False):
    sent_pcap = find_pcap(log_dir, SENT_IFACE, "out")
    recv_pcap = find_pcap(log_dir, RECV_IFACE, "in")

    if not sent_pcap or not recv_pcap:
        return None

    legit_ip = legit_ip_for(is_v6=is_v6)

    try:
        from scapy.all import PcapReader
    except ImportError:
        return None

    legit_sent = 0
    attack_sent = 0
    try:
        with PcapReader(sent_pcap) as reader:
            for p in reader:
                src = tcp_source(p, is_v6=is_v6)
                if src is None:
                    continue
                if src == legit_ip:
                    legit_sent += 1
                else:
                    attack_sent += 1
    except Exception:
        pass

    legit_recv = 0
    attack_recv = 0
    try:
        with PcapReader(recv_pcap) as reader:
            for p in reader:
                src = tcp_source(p, is_v6=is_v6)
                if src is None:
                    continue
                if src == legit_ip:
                    legit_recv += 1
                else:
                    attack_recv += 1
    except Exception:
        pass

    if legit_sent == 0 and attack_sent == 0:
        return None
    ddr = (legit_recv / legit_sent) * 100 if legit_sent > 0 else 100.0
    fnr = (attack_recv / attack_sent) * 100 if attack_sent > 0 else 0.0
    return (ddr, fnr)


def packet_count_series(log_dir, is_v6=False, source_filter=None, max_time=MAX_TIME):
    sent_pcap = find_pcap(log_dir, SENT_IFACE, "out")
    recv_pcap = find_pcap(log_dir, RECV_IFACE, "in")

    if not sent_pcap or not recv_pcap:
        return None

    from scapy.all import PcapReader

    start_t = None
    for pcap in (sent_pcap, recv_pcap):
        try:
            with PcapReader(pcap) as reader:
                for packet in reader:
                    src = tcp_source(packet, is_v6=is_v6)
                    if src is None:
                        continue
                    if source_filter is None or source_filter(src):
                        start_t = float(packet.time)
                        break
        except Exception:
            pass
        if start_t is not None:
            break

    if start_t is None:
        return None

    def count_bins(pcap):
        bins = [0] * max_time
        try:
            with PcapReader(pcap) as reader:
                for packet in reader:
                    src = tcp_source(packet, is_v6=is_v6)
                    if src is None:
                        continue
                    if source_filter is not None and not source_filter(src):
                        continue
                    t = int(float(packet.time) - start_t)
                    if 0 <= t < max_time:
                        bins[t] += 1
        except Exception:
            pass
        return bins

    return count_bins(sent_pcap), count_bins(recv_pcap)


def plot_packet_count_series(exp_name, scenario, title_subject, flow_label, source_filter):
    runs = [d for d in os.listdir(f"out/{exp_name}") if d.startswith("run_")]
    if not runs:
        return

    is_v6 = exp_name == "v6_ext"
    legit_ip = legit_ip_for(exp_name)

    max_time = MAX_TIME
    sent_bins_all = []
    recv_bins_all = []

    for run in runs:
        log_dir = f"out/{exp_name}/{run}/{scenario}"
        series = packet_count_series(
            log_dir,
            is_v6=is_v6,
            source_filter=lambda src: source_filter(src, legit_ip),
            max_time=max_time,
        )
        if series is None:
            continue
        sent_bins, recv_bins = series

        sent_bins_all.append(sent_bins)
        recv_bins_all.append(recv_bins)

    if sent_bins_all and recv_bins_all:
        sent_mean = np.mean(sent_bins_all, axis=0)
        recv_mean = np.mean(recv_bins_all, axis=0)

        sent_err = (
            st.sem(sent_bins_all, axis=0)
            if len(sent_bins_all) > 1
            else np.zeros(max_time)
        )
        recv_err = (
            st.sem(recv_bins_all, axis=0)
            if len(recv_bins_all) > 1
            else np.zeros(max_time)
        )

        time_axis = np.arange(max_time)

        plt.figure(figsize=(8, 5))
        plt.plot(time_axis, sent_mean, label=f"Enviado ({flow_label})", color="blue")
        plt.plot(time_axis, recv_mean, label="Recebido (Servidor)", color="red")

        plt.fill_between(
            time_axis,
            sent_mean - sent_err,
            sent_mean + sent_err,
            color="blue",
            alpha=0.15,
        )
        plt.fill_between(
            time_axis,
            recv_mean - recv_err,
            recv_mean + recv_err,
            color="red",
            alpha=0.15,
        )

        plt.xlabel("Tempo (s)")
        plt.ylabel("Taxa de Pacotes (pps)")

        is_ext = "ext" in exp_name
        impl_name = "P4DropExt" if is_ext else "P4Drop"
        proto = "IPv6" if "v6" in exp_name else "IPv4"
        plotted_runs = len(sent_bins_all)
        run_suffix = "Execuções" if plotted_runs > 1 else "Execução"
        plt.title(
            f"{impl_name} - {title_subject} ({proto}) ({plotted_runs} {run_suffix})"
        )

        plt.grid(True, alpha=0.3)
        plt.legend()
        plt.tight_layout()
        plt.savefig(f"out/{exp_name}_{scenario}.png")
        plt.close()


def analyze_spoofed(exp_name):
    plot_packet_count_series(
        exp_name,
        "spoof",
        "Eficácia de Fluxo de Atacante Único",
        "Atacante",
        lambda src, legit_ip: src != legit_ip,
    )


def analyze_legit(exp_name):
    plot_packet_count_series(
        exp_name,
        "legit",
        "Fluxo Legítimo Único",
        "Legítimo",
        lambda src, legit_ip: src == legit_ip,
    )


def aggregate_and_plot(exp_name):
    analyze_spoofed(exp_name)
    analyze_legit(exp_name)

    ratios = MIXED_RATIOS
    ddr_data = {r: [] for r in ratios}
    fnr_data = {r: [] for r in ratios}

    runs = [d for d in os.listdir(f"out/{exp_name}") if d.startswith("run_")]
    if not runs:
        print(f"No runs found for {exp_name}")
        return

    for run in runs:
        for ratio in ratios:
            log_dir = f"out/{exp_name}/{run}/mixed_{ratio}"
            res = analyze_mixed_run(log_dir, is_v6=(exp_name == "v6_ext"))
            if res:
                ddr, fnr = res
                ddr_data[ratio].append(ddr)
                fnr_data[ratio].append(fnr)

    x_labels = [f"{float(r) * 100}%" for r in ratios]

    ddr_means = [np.mean(ddr_data[r]) if ddr_data[r] else 0 for r in ratios]
    ddr_errs = [st.sem(ddr_data[r]) if len(ddr_data[r]) > 1 else 0 for r in ratios]
    fnr_means = [np.mean(fnr_data[r]) if fnr_data[r] else 0 for r in ratios]
    fnr_errs = [st.sem(fnr_data[r]) if len(fnr_data[r]) > 1 else 0 for r in ratios]

    plt.figure(figsize=(10, 5))
    plt.errorbar(
        x_labels,
        ddr_means,
        yerr=ddr_errs,
        marker="o",
        label="Taxa de Entrega de Pacotes (Legítimos)",
        color="green",
        capsize=5,
        capthick=2,
    )
    plt.errorbar(
        x_labels,
        fnr_means,
        yerr=fnr_errs,
        marker="x",
        label="Taxa de Falsos Negativos (Ataque Passou)",
        color="red",
        capsize=5,
        capthick=2,
    )

    plt.xlabel("Razão de Fluxo de Ataque (%)")
    plt.ylabel("Porcentagem (%)")

    is_ext = "ext" in exp_name
    impl_name = "P4DropExt" if is_ext else "P4Drop"
    proto = "IPv6" if "v6" in exp_name else "IPv4"
    run_suffix = "Execuções" if len(runs) > 1 else "Execução"
    plt.title(f"{impl_name} - Desempenho Misto ({proto}) ({len(runs)} {run_suffix})")

    plt.ylim(-5, 105)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"out/{exp_name}_mixed.png")
    plt.close()


if __name__ == "__main__":
    if os.path.exists("out/v4_base"):
        print("Analyzing v4_base...")
        aggregate_and_plot("v4_base")
    if os.path.exists("out/v4_ext"):
        print("Analyzing v4_ext...")
        aggregate_and_plot("v4_ext")
    if os.path.exists("out/v6_ext"):
        print("Analyzing v6_ext...")
        aggregate_and_plot("v6_ext")

    print("Plots saved in out/ directory.")
