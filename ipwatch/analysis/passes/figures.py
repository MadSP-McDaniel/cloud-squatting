import os
from collections import Counter, defaultdict

import numpy as np
from ipwatch.analysis.passes.util import read_flows, Flow, read_port_stats, read_stats
from matplotlib import colors
from matplotlib import pyplot as plt
from functools import lru_cache as cache


# @cache
def mem_subplots():
    return plt.subplots()


def subplots():
    plt.clf()
    plt.cla()
    plt.close()
    fig, ax = plt.subplots()
    return fig, ax


def count_flow_hist(
    data, xlabel, ylabel, legend_label, pdfname, max_storage={}, bins=100
):
    x, y, weights = zip(*data)
    max_storage["x"] = max(max_storage.get("x", 0), max(x))
    max_storage["y"] = max(max_storage.get("y", 0), max(y))
    max_storage["min_x"] = min(max_storage.get("x", 0), min(x))
    max_storage["min_y"] = min(max_storage.get("y", 0), min(y))
    xbins = np.geomspace(max_storage["min_x"], max_storage["x"], bins)
    ybins = np.geomspace(max_storage["min_y"], max_storage["y"], bins)
    counts, _, _ = np.histogram2d(x, y, bins=(xbins, ybins), weights=weights)
    max_storage["vmax"] = max(max_storage.get("vmax", 0), np.max(counts))

    fig, ax = subplots()
    m = ax.pcolormesh(
        xbins, ybins, counts.T, norm=colors.LogNorm(vmax=max_storage["vmax"])
    )
    fig.colorbar(m, label=legend_label)

    ax.set_xscale("log")
    ax.set_yscale("log")

    ax.set_ylabel(ylabel)
    ax.set_xlabel(xlabel)

    plt.savefig(pdfname)


@cache
# Returns the set of source ips in the pcap
def src_ip_set(pcap) -> set:
    if not pcap:
        return set()
    return {stat.src for stat in read_stats(blocklist)}


@cache
def source_ip_port_statistics(pcap, blocklist=None):
    blocklist_ips = {flow.src for flow in read_stats(blocklist)} if blocklist else set()

    dst_ip_ports = {}
    dst_ips = {}
    dst_ports = {}
    dst_flows = Counter()

    for src, ips, ports, pairs, flows in read_stats(pcap):
        if src in blocklist_ips:
            continue
        dst_ip_ports[src] = pairs
        dst_ips[src] = ips
        dst_ports[src] = ports
        dst_flows[src] = flows

    return dst_ip_ports, dst_ips, dst_ports, dst_flows


# This figure (Same as 3a in Scanning the Scanners) shows density of source IPs hitting various destination IPs
def ip_packets_per_source(pcap, target, blocklist=None, max_storage={}):
    os.makedirs(os.path.join(target), exist_ok=True)
    sources, source_ips, source_ports, flows = source_ip_port_statistics(
        pcap, blocklist
    )
    print("Done reading flows")
    for weighting, name in [(lambda k: flows[k], "connections"), (lambda k: 1, "ips")]:
        os.makedirs(os.path.join(target, name), exist_ok=True)

        count_flow_hist(
            [(v, flows[k], weighting(k)) for k, v in sources.items()],
            "Number of destination (IP,port) pairs contacted",
            "Number of connections from source IP",
            name,
            os.path.join(target, name, f"ip_packets_per_source_ip_port.pdf"),
            max_storage.setdefault(f"{name}_packets_per_source_ip_port", {}),
        )
        count_flow_hist(
            [(v, flows[k], weighting(k)) for k, v in source_ips.items()],
            "Number of destination IPs contacted",
            "Number of connections from source IP",
            name,
            os.path.join(target, name, f"packets_per_source_ip.pdf"),
            max_storage.setdefault(f"{name}_packets_per_source_ip", {}),
        )
        count_flow_hist(
            [(v, flows[k], weighting(k)) for k, v in source_ports.items()],
            "Number of destination ports contacted",
            "Number of connections from source IP",
            name,
            os.path.join(target, name, f"packets_per_source_port.pdf"),
            max_storage.setdefault(f"{name}_packets_per_source_port", {}),
        )
        count_flow_hist(
            [(source_ips[k], v, weighting(k)) for k, v in source_ports.items()],
            "Number of destination IPs contacted",
            "Number of destination ports contacted",
            name,
            os.path.join(target, name, f"num_ports_num_ips.pdf"),
            max_storage.setdefault(f"{name}_num_ports_num_ips", {}),
        )


@cache
def _flow_histogram(pcap, filt=None):
    return [stat.sessions for stat in read_stats(pcap)]


def flow_histogram(pcap, target):
    os.makedirs(os.path.join(target), exist_ok=True)
    fig, ax = subplots()
    sessions = _flow_histogram(pcap)
    xbins = np.geomspace(min(sessions), max(sessions), 20)
    ax.hist(
        sessions,
        weights=sessions,
        bins=xbins,
        # bins=[1, 2, 5, 10, 20, 50, 100, 200, 500, 1000],
    )
    ax.set_xscale("log")

    ax.set_xlabel("Number of TCP sessions from IP")
    ax.set_ylabel("Number of TCP sessions")

    plt.savefig(os.path.join(target, "num_sessions_per_ip.pdf"))


def cum_flow_histogram(pcaps, names, target):
    os.makedirs(os.path.join(target), exist_ok=True)
    histograms = [_flow_histogram(pcap) for pcap in pcaps]
    fig, ax = subplots()
    xbins = np.geomspace(
        min(min(sessions) for sessions in histograms),
        max(max(sessions) for sessions in histograms),
        20,
    )
    for sessions, name in zip(histograms, names):

        y, x = np.histogram(sessions, weights=sessions, bins=xbins)
        y = np.cumsum(y)
        y = y / max(y)
        ax.plot(x[:-1], y, label=name)
        ax.set_xscale("log")

        ax.set_xlabel("Number of TCP sessions from IP")
        ax.set_ylabel("Fraction of TCP sessions")

    plt.legend()

    plt.savefig(os.path.join(target, "cumulative.pdf"))


def flow_interval_graphs(diffs, target):

    if len(diffs) < 2:
        return

    os.makedirs(os.path.join(target), exist_ok=True)

    combined_diffs = [j for i in diffs for j in i]

    fig, ax = subplots()
    ax.hist(
        combined_diffs,
        bins=50,
    )

    ax.set_xlabel("Duration since last connection on same src-dst-dstport")
    ax.set_ylabel("Number of TCP sessions")

    plt.savefig(os.path.join(target, "flow_interval_histogram.pdf"))

    fig, ax = subplots()
    ax.hist(
        combined_diffs,
        bins=np.geomspace(min(combined_diffs), max(combined_diffs), 50),
    )
    ax.set_xscale("log")

    ax.set_xlabel("Duration since last connection on same src-dst-dstport")
    ax.set_ylabel("Number of TCP sessions")

    plt.savefig(os.path.join(target, "flow_interval_histogram_log.pdf"))

    medians = [np.median(i) for i in diffs]
    connection_counts = [len(i) + 1 for i in diffs]

    if len(medians) > 1:
        fig, ax = subplots()
        ax.hist(
            medians,
            bins=np.geomspace(min(medians), max(medians), 50),
        )
        ax.set_xscale("log")

        ax.set_xlabel("Median duration since last connection on same src-dst-dstport")
        ax.set_ylabel("Number of src-dst pairs")

        plt.savefig(os.path.join(target, "flow_interval_median_histogram_log.pdf"))

        if len(medians) > 10:
            count_flow_hist(
                [
                    (medians[i], connection_counts[i], connection_counts[i])
                    for i in range(len(medians))
                ],
                "Median duration since last connection on same src-dst-dstport",
                "Number of connections",
                "connections",
                os.path.join(target, "flow_interval_median_vs_connections_log.pdf"),
                {},
                bins=100,
            )
            plt.plot([min(medians), 3600], [3600 / min(medians), 2])
            plt.savefig(
                os.path.join(target, "flow_interval_median_vs_connections_log.pdf")
            )

        else:

            fig, ax = subplots()
            ax.scatter(medians, connection_counts)
            ax.set_xscale("log")
            ax.set_yscale("log")

            ax.set_xlabel(
                "Median duration since last connection on same src-dst-dstport"
            )
            ax.set_ylabel("Number of connections")

            plt.savefig(
                os.path.join(target, "flow_interval_median_vs_connections_log.pdf")
            )


# Shows the intervals between connections from each host on a given dst ip/port.
def flow_interval_histogram(pcap, target, port=None):
    os.makedirs(os.path.join(target), exist_ok=True)

    src_dst_sets = defaultdict(lambda: set())

    for src, srcport, dst, dstport, t in read_flows(pcap):
        src_dst_sets[(src, dst, int(dstport))].add(float(t))

    print(f"Total src-dst pairs: {len(src_dst_sets)}")

    src_dst_sets = {k: list(sorted(v)) for k, v in src_dst_sets.items()}
    src_dst_sets = {
        k: [j - i for i, j in zip(v[:-1], v[1:])]
        for k, v in src_dst_sets.items()
        if len(v) > 1
    }  # take element-wise differences
    print(f"With multiple connections: {len(src_dst_sets)}")

    all_diffs = defaultdict(lambda: [])

    for k, v in src_dst_sets.items():
        all_diffs[k[2]].append([max(i, 0.001) for i in v])

    print(f"Total ports coverered: {len(all_diffs)}")

    flow_interval_graphs(
        [diff for diffs in all_diffs.values() for diff in diffs],
        os.path.join(target, "comb"),
    )

    for current_port in sorted(all_diffs.keys()):
        if port and current_port != port:
            continue
        if sum(len(i) for i in all_diffs[current_port]) < 2:
            continue

        print(f"Plotting port {current_port}")

        diffs = all_diffs[current_port]

        flow_interval_graphs(diffs, os.path.join(target, str(current_port)))


"""
    # 1d histogram of flows over IP,port pairs
    x, weights = zip(*((len(v), flows[k]) for k, v in sources.items()))
    xbins = [1, 2, 3, 4, 5, 6, 7, 8, 9] + list(
        10 ** np.linspace(1, np.log10(max(x)), 10)
    )
    values, base = np.histogram(x, bins=xbins, weights=weights)
    cumulative = np.np.cumsum(values)

    fig, ax = subplots()
    ax.bar([str(l) for l in xbins], values)
    ax.plot([str(l) for l in xbins], cumulative)

    ax.set_xlabel("Number of (IP,port) pairs contacted")
    ax.set_ylabel("Number of TCP sessions")
    # ax.set_yscale('log')

    plt.savefig(os.path.join(target, "num_ip_port_sessions.pdf"))
"""


# Plots the most common ports as a stacked bar graph, as they are filtered down by analysis passes
# Inputs are from most to least specific
def ports_filtered(target, input_ips, input_ports, labels):
    os.makedirs(os.path.join(target), exist_ok=True)
    sessions = []
    ips = []
    ipcounts = []
    # dstips = []
    for i in range(len(input_ips)):
        print(f"Reading input {i}")
        port_sessions = Counter()
        port_ips = Counter()
        ip_count = 0
        for port, session_count, ip_count in read_port_stats(input_ports[i]):
            port_sessions[port] = session_count
            port_ips[port] = ip_count
        print(f"Reading input {i} ips")
        with open(input_ips[i]) as f:
            for _ in f:
                ip_count += 1

        sessions.append(port_sessions)
        ips.append(port_ips)
        # dstips.append(Counter({k: len(v) for k, v in dstipdict.items()}))
        ipcounts.append(ip_count)
    for num_layers in range(1, len(labels) + 1):
        max_layer = labels[num_layers - 1]
        for order_index, ordering in (
            (lambda x: x[0], "specific"),
            (lambda x: x[-1], "broad"),
            (lambda x: x[-1] - (x[-2:][0]), "filtered"),
        ):
            for counts, ylabel, pdfname in (
                (sessions, "Number of sessions", f"sessions_{ordering}.pdf"),
                (ips, "Number of ips", f"ips_{ordering}.pdf"),
                # (dstips, "Number of dst ips", f"dstips_{ordering}.pdf"),
            ):
                fig, ax = subplots()
                fig.set_size_inches((15, 3.5))

                subcounts = counts[:num_layers]
                sublabels = ["Final results"] + labels[: num_layers - 1]
                max_label = f"{num_layers}_{labels[num_layers - 1]}"
                os.makedirs(os.path.join(target, max_label), exist_ok=True)

                cumulative = Counter()
                port_keys = [k for k, v in order_index(subcounts).most_common(20)]
                for count, label in zip(subcounts, sublabels):
                    bottom = [cumulative[key] for key in port_keys]
                    subtracted = count - cumulative
                    data = [subtracted[key] for key in port_keys]
                    cumulative = count
                    ax.bar(port_keys, data, label=label, bottom=bottom)

                ax.set_ylabel(ylabel)
                ax.set_xlabel("TCP Port")
                ax.set_yscale("log")

                ax.legend()

                plt.savefig(os.path.join(target, max_label, pdfname))

    for counts, label, pdfname in (
        (
            [sum(session.values()) for session in sessions],
            "Remaining sessions",
            f"session_funnel.pdf",
        ),
        (ipcounts, "Remaining ips", f"ip_funnel.pdf"),
    ):

        fig, ax = subplots()
        fig.set_size_inches((10, 5))
        data = []
        for count in reversed(counts):
            data.append(count)

        rects = ax.bar(list(reversed(labels)), data)

        ax.set_ylabel(label)
        ax.set_xlabel("Filter step")
        for rect, label in zip(rects, data):
            height = rect.get_height()
            ax.text(
                rect.get_x() + rect.get_width() / 2,
                height + 5,
                label,
                ha="center",
                va="bottom",
            )
        ax.set_yscale("log")

        os.makedirs(os.path.join(target, "funnel"), exist_ok=True)
        plt.savefig(os.path.join(target, "funnel", pdfname))


def load_ts(timestamps, mod=None, round_v=1):
    with open(timestamps) as f:
        values = Counter()
        for l in f:
            ts, count = (int(i) for i in l.split())
            if mod:
                ts = ts % mod
            ts = ts // round_v * round_v
            values[ts] += count
        return values


def timestamps(target, timestamps, norm=None, mod=None, round_v=1):
    values = load_ts(timestamps, mod, round_v)
    if norm:
        norm = load_ts(norm, mod, round_v)
        values = {k: v / norm[k] for k, v in values.items() if k in norm}
    x = list(sorted(values.keys()))
    y = [values[i] for i in x]
    fig, ax = subplots()
    fig.set_size_inches((10, 5))

    rects = ax.plot(x, y)

    ax.set_ylabel("Number of sessions")
    ax.set_xlabel("Time (seconds)")

    plt.savefig(os.path.join(target))


def timestamps_filtered(target, timestamps, labels, mod=None, round_v=1):
    values = [load_ts(ts, mod, round_v) for ts in timestamps]
    X = list(sorted({k for v in values for k in v.keys()}))

    fig, ax = subplots()
    ax.set_yscale("log")
    fig.set_size_inches((10, 5))
    for i, label in enumerate(labels):
        y = [values[i].get(x, 0) for x in X]
        ax.fill_between(X, y, label=label)

    ax.set_ylabel("Number of sessions")
    ax.set_xlabel("Time (seconds)")

    plt.savefig(os.path.join(target))


def figures(target, args):
    os.makedirs(os.path.join(target, "figures"), exist_ok=True)
    """
    timestamps(
        os.path.join(target, "figures", "timestamps.pdf"),
        os.path.join(target, "inbound_only", "timestamps.tsv"),
        round_v=3600,
    )
    timestamps(
        os.path.join(target, "figures", "timestamps_hour.pdf"),
        os.path.join(target, "inbound_only", "timestamps.tsv"),
        mod=3600,
    )
    timestamps(
        os.path.join(target, "figures", "timestamps_minute.pdf"),
        os.path.join(target, "inbound_only", "timestamps.tsv"),
        mod=60,
    )
    timestamps(
        os.path.join(target, "figures", "timestamps_day.pdf"),
        os.path.join(target, "inbound_only", "timestamps.tsv"),
        mod=86400,
        round_v=600,
    )
    timestamps(
        os.path.join(target, "figures", "timestamps_day_nodup_share.pdf"),
        os.path.join(target, "no_dups", "timestamps.tsv"),
        os.path.join(target, "inbound_only", "timestamps.tsv"),
        mod=86400,
        round_v=600,
    )
    timestamps(
        os.path.join(target, "figures", "timestamps_day_legit_share.pdf"),
        os.path.join(target, "tshark_rules", "timestamps.tsv"),
        os.path.join(target, "inbound_only", "timestamps.tsv"),
        mod=86400,
        round_v=600,
    )"""

    """
    cum_flow_histogram(
        [
            os.path.join(target, "tshark_rules", "ip_port_stats.tsv"),
            os.path.join(target, "payload", "ip_port_stats.tsv"),
            os.path.join(target, "no_dups", "ip_port_stats.tsv"),
            os.path.join(target, "blocklists", "ip_port_stats.tsv"),
            os.path.join(target, "inbound_only", "ip_port_stats.tsv"),
        ],
        [
            "application",
            "session",
            "transport",
            "network",
            "inbound",
        ],
        os.path.join(target, "figures", "flow_histogram"),
    )
    print("cdone")
    flow_histogram(
        os.path.join(target, "snort_rules", "ip_port_stats.tsv"),
        os.path.join(target, "figures", "flow_histogram", "snort"),
    )
    flow_histogram(
        os.path.join(target, "tshark_rules", "ip_port_stats.tsv"),
        os.path.join(target, "figures", "flow_histogram", "exploits"),
    )
    flow_histogram(
        os.path.join(target, "inbound_only", "ip_port_stats.tsv"),
        os.path.join(target, "figures", "flow_histogram", "inbound"),
    )
    flow_histogram(
        os.path.join(target, "no_dups", "ip_port_stats.tsv"),
        os.path.join(target, "figures", "flow_histogram", "no_dups"),
    )
    print("done")
    flow_interval_histogram(
        os.path.join(target, "tshark_rules", "ip_ports.tsv"),
        os.path.join(target, "figures", "flow_interval_histogram", "tshark_rules"),
        port=9200,
    )
    flow_interval_histogram(
        os.path.join(target, "inbound_only", "ip_ports.tsv"),
        os.path.join(target, "figures", "flow_interval_histogram", "inbound"),
        port=9200,
    )"""
    """
    max_storage = {}
    print("inbound")
    ip_packets_per_source(
        os.path.join(target, "inbound_only", "ip_port_stats.tsv"),
        os.path.join(target, "figures", "ip_packets_per_source", "inbound"),
        max_storage=max_storage,
    )
    print("block")
    ip_packets_per_source(
        os.path.join(target, "blocklists", "ip_port_stats.tsv"),
        os.path.join(target, "figures", "ip_packets_per_source", "blocklist"),
        max_storage=max_storage,
    )
    print("diff")
    ip_packets_per_source(
        os.path.join(target, "inbound_only", "ip_port_stats.tsv"),
        os.path.join(target, "figures", "ip_packets_per_source", "blocklist_diff"),
        os.path.join(target, "blocklists", "ip_port_stats.tsv"),
        max_storage=max_storage,
    )"""
    timestamps_filtered(
        os.path.join(target, "figures", "timestamps_stacked.pdf"),
        [
            os.path.join(target, "inbound_only", "timestamps.tsv"),
            os.path.join(target, "blocklists", "timestamps.tsv"),
            os.path.join(target, "no_dups", "timestamps.tsv"),
            os.path.join(target, "snort_rules", "timestamps.tsv"),
            os.path.join(target, "tshark_rules", "timestamps.tsv"),
        ],
        ["inbound", "blocklists", "no_dups", "snort_rules", "tshark_rules"],
        round_v=3600,
    )
    timestamps_filtered(
        os.path.join(target, "figures", "timestamps_day_stacked.pdf"),
        [
            os.path.join(target, "inbound_only", "timestamps.tsv"),
            os.path.join(target, "blocklists", "timestamps.tsv"),
            os.path.join(target, "no_dups", "timestamps.tsv"),
            os.path.join(target, "snort_rules", "timestamps.tsv"),
            os.path.join(target, "tshark_rules", "timestamps.tsv"),
        ],
        ["inbound", "blocklists", "no_dups", "snort_rules", "tshark_rules"],
        mod=86400,
        round_v=600,
    )
    timestamps_filtered(
        os.path.join(target, "figures", "timestamps_hour_stacked.pdf"),
        [
            os.path.join(target, "inbound_only", "timestamps.tsv"),
            os.path.join(target, "blocklists", "timestamps.tsv"),
            os.path.join(target, "no_dups", "timestamps.tsv"),
            os.path.join(target, "snort_rules", "timestamps.tsv"),
            os.path.join(target, "tshark_rules", "timestamps.tsv"),
        ],
        ["inbound", "blocklists", "no_dups", "snort_rules", "tshark_rules"],
        mod=3600,
        round_v=60,
    )
    timestamps_filtered(
        os.path.join(target, "figures", "timestamps_minute_stacked.pdf"),
        [
            os.path.join(target, "inbound_only", "timestamps.tsv"),
            os.path.join(target, "blocklists", "timestamps.tsv"),
            os.path.join(target, "no_dups", "timestamps.tsv"),
            os.path.join(target, "snort_rules", "timestamps.tsv"),
            os.path.join(target, "tshark_rules", "timestamps.tsv"),
        ],
        ["inbound", "blocklists", "no_dups", "snort_rules", "tshark_rules"],
        mod=60,
    )
    """
    ports_filtered(
        os.path.join(target, "figures", "ports_filtered"),
        [
            os.path.join(target, "tshark_rules", "ip_port_stats.tsv"),
            os.path.join(target, "payload", "ip_port_stats.tsv"),
            os.path.join(target, "no_dups", "ip_port_stats.tsv"),
            os.path.join(target, "blocklists", "ip_port_stats.tsv"),
            os.path.join(target, "inbound_only", "ip_port_stats.tsv"),
        ],
        [
            os.path.join(target, "tshark_rules", "port_stats.tsv"),
            os.path.join(target, "payload", "port_stats.tsv"),
            os.path.join(target, "no_dups", "port_stats.tsv"),
            os.path.join(target, "blocklists", "port_stats.tsv"),
            os.path.join(target, "inbound_only", "port_stats.tsv"),
        ],
        [
            "application",
            "session",
            "transport",
            "network",
            "inbound",
        ],
    )
    
    ports_filtered(
        os.path.join(target, "figures", "ports_filtered_apprules"),
        [
            os.path.join(target, "tshark_rules", "ip_port_stats.tsv"),
            os.path.join(target, "tshark_rules", "exploits_ip_port_stats.tsv"),
            os.path.join(target, "payload", "ip_port_stats.tsv"),
            os.path.join(target, "no_dups", "ip_port_stats.tsv"),
            os.path.join(target, "blocklists", "ip_port_stats.tsv"),
            os.path.join(target, "inbound_only", "ip_port_stats.tsv"),
        ],
        [
            os.path.join(target, "tshark_rules", "port_stats.tsv"),
            os.path.join(target, "tshark_rules", "exploits_port_stats.tsv"),
            os.path.join(target, "payload", "port_stats.tsv"),
            os.path.join(target, "no_dups", "port_stats.tsv"),
            os.path.join(target, "blocklists", "port_stats.tsv"),
            os.path.join(target, "inbound_only", "port_stats.tsv"),
        ],
        [
            "application",
            "snort",
            "session",
            "transport",
            "network",
            "inbound",
        ],
    )
    
    ports_filtered(
        os.path.join(target, "figures", "ports_filtered_noapprules"),
        [
            os.path.join(target, "payload", "ip_ports.tsv"),
            os.path.join(target, "ack", "ip_ports.tsv"),
            os.path.join(target, "no_dups", "ip_ports.tsv"),
            os.path.join(target, "blocklists", "ip_ports.tsv"),
            os.path.join(target, "inbound_only", "ip_ports.tsv"),
        ],
        ["payload", "ack", "no_dups", "blocklists", "inbound",],
    )"""
