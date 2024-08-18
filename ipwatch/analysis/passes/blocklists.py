import os

import requests
from ipwatch.analysis.passes.util import is_local, write_flows
from ipwatch.analysis.passes.util.blocklist import blocklist


def blocklists(target, args):

    os.makedirs(os.path.join(target, "blocklists"), exist_ok=True)

    blocklist_urls = [
        "https://iplists.firehol.org/files/firehol_level1.netset",
        "https://iplists.firehol.org/files/firehol_level2.netset",
        "https://iplists.firehol.org/files/firehol_level3.netset",
        "https://iplists.firehol.org/files/firehol_level4.netset",
    ]

    joined_lists = ""

    ips = []

    for url in blocklist_urls:
        joined_lists += "\n" + requests.get(url).text

    for line in joined_lists.split("\n"):
        ip = line.split("#")[0].strip()
        if not ip:
            continue
        if is_local(ip):
            continue
        ips.append(ip)

    blocklist(
        os.path.join(target, "inbound_only", "filtered.pcap"),
        os.path.join(target, "blocklists", "filtered.pcap"),
        os.path.join(target, "blocklists", "tmp"),
        "\n".join(ips),
    )
    print("Performing ip/port statistics")
    write_flows(
        os.path.join(target, "blocklists", "filtered.pcap"),
        os.path.join(target, "blocklists", ""),
    )
