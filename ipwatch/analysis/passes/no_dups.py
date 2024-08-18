import os
import subprocess
from collections import Counter, defaultdict

from ipwatch.analysis.passes.util import read_stats, write_flows
from ipwatch.analysis.passes.util.blocklist import blocklist
from matplotlib import pyplot as plt


def set_size_statistics(d, max_buckets=[10, 100, 1000], ip_flows=None):
    c = Counter()
    for k, l in d.items():
        if l > min(max_buckets):  # Bucketize to log buckets after a certain point
            l = max(m for m in max_buckets if m <= l)
        if ip_flows:
            c[l] += ip_flows[k]
        else:
            c[l] += 1
    return c


def duplicate_histogram(
    name,
    sources,
    preblack,
    label,
    title,
    max_buckets=[10, 100, 1000, 10000],
    ip_flows=None,
):
    sources = set_size_statistics(sources, max_buckets, ip_flows)
    preblack = set_size_statistics(preblack, max_buckets, ip_flows)
    preblack.subtract(sources)

    labels = list(sorted(preblack.keys()))
    sources = [sources[i] for i in labels]
    preblack = [preblack[i] for i in labels]
    width = 0.35  # the width of the bars: can also be len(x) sequence

    fig, ax = plt.subplots()

    ax.bar([str(l) for l in labels], sources, width, label="After blocklist")
    ax.bar(
        [str(l) for l in labels], preblack, width, label="Pre-blocklist", bottom=sources
    )

    if ip_flows:
        ax.set_ylabel("Number of Flows")
    else:
        ax.set_ylabel("Number of IPs")
    ax.set_title(label)
    # ax.set_yscale('log')
    ax.legend()

    plt.savefig(name)


def no_dups(target, args):

    os.makedirs(os.path.join(target, "no_dups"), exist_ok=True)

    sources = {}
    sources_ips = {}
    sources_ports = {}
    sources_preblack = {}
    sources_ips_preblack = {}
    sources_ports_preblack = {}
    ip_flows = Counter()

    for src, ips, ports, pairs, sessions in read_stats(
        os.path.join(target, "blocklists", "ip_port_stats.tsv")
    ):
        sources[src] = pairs
        sources_ips[src] = ips
        sources_ports[src] = ports
    """
    for src, ips, ports, pairs, sessions in read_stats(
        os.path.join(target, "inbound_only", "ip_port_stats.tsv")
    ):
        sources_preblack[src] = pairs
        sources_ips_preblack[src] = ips
        sources_ports_preblack[src] = ports
        ip_flows[src] = sessions

    duplicate_histogram(
        os.path.join(target, "no_dups", "ports+ips.pdf"),
        sources,
        sources_preblack,
        "Number of (ip,port) pairs hit",
        "Histogram of (ip,port) pairs hit by source IPs",
    )
    duplicate_histogram(
        os.path.join(target, "no_dups", "port+ip_flows.pdf"),
        sources,
        sources_preblack,
        "Number of (ip,port) pairs hit",
        "Histogram of (ip,port) pairs hit",
        ip_flows=ip_flows,
    )
    duplicate_histogram(
        os.path.join(target, "no_dups", "ports.pdf"),
        sources_ports,
        sources_ports_preblack,
        "Number of ports hit",
        "Histogram of Ports hit by source IPs",
    )
    duplicate_histogram(
        os.path.join(target, "no_dups", "port_flows.pdf"),
        sources_ports,
        sources_ports_preblack,
        "Number of ports hit",
        "Histogram of Ports hit",
        ip_flows=ip_flows,
    )
    duplicate_histogram(
        os.path.join(target, "no_dups", "ips.pdf"),
        sources_ips,
        sources_ips_preblack,
        "Number of IPs hit",
        "Histogram of IPs hit by source IPs",
    )
    duplicate_histogram(
        os.path.join(target, "no_dups", "ip_flows.pdf"),
        sources_ips,
        sources_ips_preblack,
        "Number of IPs hit",
        "Histogram of IPs hit",
        ip_flows=ip_flows,
    )
"""
    get_dups = lambda x: set(ip for ip, targets in x.items() if targets > 1)

    dup_ips = get_dups(sources)
    """
    with open(os.path.join(target, "no_dups", "stats.txt"), "w") as f:
        f.write(
            f"Preblock: {len(get_dups(sources_preblack))} of {len(sources_preblack)} were dups on ip/port\n"
            f"          {len(get_dups(sources_ips_preblack))} of {len(sources_ips_preblack)} were dups on ip\n"
            f"          {len(get_dups(sources_ports_preblack))} of {len(sources_ports_preblack)} were dups on port\n"
        )
        f.write(
            f"Postblock: {len(get_dups(sources))} of {len(sources)} were dups on ip/port\n"
            f"           {len(get_dups(sources_ips))} of {len(sources_ips)} were dups on ip\n"
            f"           {len(get_dups(sources_ports))} of {len(sources_ports)} were dups on port\n"
        )
"""
    print(f"Found {len(dup_ips)} duplicate IPs")

    blocklist(
        os.path.join(target, "blocklists", "filtered.pcap"),
        os.path.join(target, "no_dups", "filtered.pcap"),
        os.path.join(target, "no_dups", "tmp"),
        "\n".join(dup_ips),
    )
    write_flows(
        os.path.join(target, "no_dups", "filtered.pcap"),
        os.path.join(target, "no_dups", ""),
    )
