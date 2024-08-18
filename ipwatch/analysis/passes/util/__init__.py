import ipaddress
import os
from collections import namedtuple
import subprocess
from functools import lru_cache as cache

Flow = namedtuple("Flow", ["src", "srcport", "dst", "dstport", "ts"])
IPStat = namedtuple("IPStat", ["src", "ips", "ports", "pairs", "sessions"])


def is_local(ip):
    return ipaddress.IPv4Network(ip).is_private


# Yields (src,dst,dstport) of all flows in the
def get_flows(pcap):
    with subprocess.Popen(
        f'{os.path.join(os.path.dirname(__file__), "ipportextract", "ipportextract")} < {pcap}',
        shell=True,
        stdout=subprocess.PIPE,
    ) as proc:
        for line in proc.stdout:
            if not line.strip():
                continue
            yield Flow(*(s.decode() for s in line.split()))


def write_flows(pcap, output):
    subprocess.check_output(
        f'{os.path.join(os.path.dirname(__file__), "ipportstats", "ipportstats")} {pcap} {output+"ip_ports.tsv"} {output+"ip_port_stats.tsv"} {output+"port_stats.tsv"}',
        shell=True,
    )


def mergecap(pcaps, output):
    subprocess.check_output(
        f'{os.path.join(os.path.dirname(__file__), "mergecap", "mergecap")} {pcaps} > {output}',
        shell=True,
    )


# mergecap2 merges all pcaps. Expects a list of (file, ip)
def mergecap2(pcaps, output):
    i = ""
    for pcap, ip in pcaps:
        i += f"{pcap}\n{ip}\n"
    subprocess.check_output(
        f'{os.path.join(os.path.dirname(__file__), "mergecap2", "mergecap2")} > {output}',
        shell=True,
        input=i.encode(),
    )


@cache
def read_flows(output):
    with open(output) as f:
        return [Flow(*line.split()) for line in f]


@cache
def read_stats(output):
    with open(output) as f:
        stats = []
        for line in f:
            src, ips, ports, pairs, flows = line.split()
            stats.append(IPStat(src, int(ips), int(ports), int(pairs), int(flows)))
        return stats


@cache
def read_port_stats(output):
    with open(output) as f:
        stats = []
        for line in f:
            port, sessions, ips = line.split()
            stats.append((port, int(sessions), int(ips)))
        return stats
