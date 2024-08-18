import os
import subprocess

from ipwatch.analysis.passes.util import is_local, write_flows, get_flows
from ipwatch.analysis.passes.util.blocklist import blocklist


def snort_rules(target, args):
    print("Filtering out IPs matching snort rules")
    print(os.getcwd())

    subprocess.check_output(["rm", "-rf", os.path.join(target, "snort_rules")])
    os.makedirs(os.path.join(target, "snort_rules"), exist_ok=True)

    # First generate the list of packets matching snort rules.
    subprocess.check_output(
        [
            "snort",
            "-r",
            os.path.join(target, "payload", "filtered.pcap"),
            "-c",
            os.path.join(os.path.dirname(__file__), "snort", "snort.conf"),
            "-l",
            os.path.join(target, "snort_rules"),
        ],
    )
    subprocess.check_output(
        f'cp {os.path.join(target, "snort_rules", "snort_rules.pcap.*")} {os.path.join(target, "snort_rules", "snort_rules.pcap")}',
        shell=True,
    )
    print(os.getcwd())
    # Use tshark to extract the IPs associated with filtered packets
    filtered_ips = {
        flow.src
        for flow in get_flows(os.path.join(target, "snort_rules", "snort_rules.pcap"))
    }

    print("Filtered IPs:", len(filtered_ips))

    blocklist(
        os.path.join(target, "payload", "filtered.pcap"),
        os.path.join(target, "snort_rules", "filtered.pcap"),
        os.path.join(target, "snort_rules", "tmp"),
        "\n".join(filtered_ips),
    )
    write_flows(
        os.path.join(target, "snort_rules", "filtered.pcap"),
        os.path.join(target, "snort_rules", ""),
    )
