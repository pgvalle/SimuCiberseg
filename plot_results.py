import glob
import os
import sys

import numpy as np
import scipy.stats as st

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from scapy.all import IP, TCP, IPv6, rdpcap
except ImportError:
    print("Please install matplotlib, scapy, numpy, scipy")
    sys.exit(1)


def find_pcap(base_dir, iface_prefix, suffix):
    pattern = os.path.join(base_dir, f"{iface_prefix}_{suffix}.pcap")
    files = glob.glob(pattern)
    if files:
        return files[0]
    return None


def analyze_single_run(log_dir, is_v6=False):
    sent_pcap = find_pcap(log_dir, "s1-eth1", "out")
    recv_pcap = find_pcap(log_dir, "s1-eth2", "in")

    if not sent_pcap or not recv_pcap:
        return None

    if is_v6:
        legit_ip = "2001:db8:1::101"
    else:
        legit_ip = "10.0.1.101"

    try:
        from scapy.all import PcapReader
    except ImportError:
        return None

    legit_sent = 0
    attack_sent = 0
    try:
        with PcapReader(sent_pcap) as reader:
            for p in reader:
                if is_v6:
                    if IPv6 in p and TCP in p:
                        if p[IPv6].src == legit_ip:
                            legit_sent += 1
                        else:
                            attack_sent += 1
                else:
                    if IP in p and TCP in p:
                        if p[IP].src == legit_ip:
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
                if is_v6:
                    if IPv6 in p and TCP in p:
                        if p[IPv6].src == legit_ip:
                            legit_recv += 1
                        else:
                            attack_recv += 1
                else:
                    if IP in p and TCP in p:
                        if p[IP].src == legit_ip:
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


def analyze_single_spoofed(exp_name):
    runs = [d for d in os.listdir(f"out/{exp_name}") if d.startswith("run_")]
    if not runs:
        return

    is_v6 = exp_name == "v6_ext"
    if is_v6:
        legit_ip = "2001:db8:1::101"
    else:
        legit_ip = "10.0.1.101"

    max_time = 60
    sent_bins_all = []
    recv_bins_all = []

    from scapy.all import PcapReader

    # Check if we have the necessary classes imported
    try:
        from scapy.all import IP, TCP, IPv6
    except ImportError:
        return

    for run in runs:
        log_dir = f"out/{exp_name}/{run}/single"
        sent_pcap = find_pcap(log_dir, "s1-eth1", "out")
        recv_pcap = find_pcap(log_dir, "s1-eth2", "in")

        if not sent_pcap or not recv_pcap:
            continue

        sent_bins = [0] * max_time
        recv_bins = [0] * max_time

        start_t = None
        try:
            with PcapReader(sent_pcap) as reader:
                for p in reader:
                    if is_v6:
                        has_ip = IPv6 in p and TCP in p
                        src = p[IPv6].src if has_ip else None
                    else:
                        has_ip = IP in p and TCP in p
                        src = p[IP].src if has_ip else None

                    if has_ip and src != legit_ip:
                        start_t = float(p.time)
                        break
        except Exception:
            pass

        if start_t is None:
            try:
                with PcapReader(recv_pcap) as reader:
                    for p in reader:
                        if is_v6:
                            has_ip = IPv6 in p and TCP in p
                            src = p[IPv6].src if has_ip else None
                        else:
                            has_ip = IP in p and TCP in p
                            src = p[IP].src if has_ip else None

                        if has_ip and src != legit_ip:
                            start_t = float(p.time)
                            break
            except Exception:
                pass

        if start_t is not None:
            try:
                with PcapReader(sent_pcap) as reader:
                    for p in reader:
                        if is_v6:
                            has_ip = IPv6 in p and TCP in p
                            src = p[IPv6].src if has_ip else None
                        else:
                            has_ip = IP in p and TCP in p
                            src = p[IP].src if has_ip else None

                        if has_ip and src != legit_ip:
                            t = int(float(p.time) - start_t)
                            if 0 <= t < max_time:
                                sent_bins[t] += 1
            except Exception:
                pass

            try:
                with PcapReader(recv_pcap) as reader:
                    for p in reader:
                        if is_v6:
                            has_ip = IPv6 in p and TCP in p
                            src = p[IPv6].src if has_ip else None
                        else:
                            has_ip = IP in p and TCP in p
                            src = p[IP].src if has_ip else None

                        if has_ip and src != legit_ip:
                            t = int(float(p.time) - start_t)
                            if 0 <= t < max_time:
                                recv_bins[t] += 1
            except Exception:
                pass

        sent_bins_all.append(sent_bins)
        recv_bins_all.append(recv_bins)

    if sent_bins_all and recv_bins_all:
        sent_mean = np.mean(sent_bins_all, axis=0)
        recv_mean = np.mean(recv_bins_all, axis=0)

        sent_err = (
            st.sem(sent_bins_all, axis=0) if len(runs) > 1 else np.zeros(max_time)
        )
        recv_err = (
            st.sem(recv_bins_all, axis=0) if len(runs) > 1 else np.zeros(max_time)
        )

        time_axis = np.arange(max_time)

        plt.figure(figsize=(8, 5))
        plt.plot(time_axis, sent_mean, label="Enviado (Atacante)", color="blue")
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
        run_suffix = "Execuções" if len(runs) > 1 else "Execução"
        plt.title(f"{impl_name} - Eficácia de Fluxo de Atacante Único ({proto}) ({len(runs)} {run_suffix})")
        
        plt.grid(True, alpha=0.3)
        plt.legend()
        plt.tight_layout()
        plt.savefig(f"out/{exp_name}_single.png")
        plt.close()



def aggregate_and_plot(exp_name):
    analyze_single_spoofed(exp_name)

    ratios = ["0.0", "0.25", "0.5", "0.75", "1.0"]
    ddr_data = {r: [] for r in ratios}
    fnr_data = {r: [] for r in ratios}

    runs = [d for d in os.listdir(f"out/{exp_name}") if d.startswith("run_")]
    if not runs:
        print(f"No runs found for {exp_name}")
        return

    for run in runs:
        for ratio in ratios:
            log_dir = f"out/{exp_name}/{run}/mixed_{ratio}"
            res = analyze_single_run(log_dir, is_v6=(exp_name == "v6_ext"))
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
