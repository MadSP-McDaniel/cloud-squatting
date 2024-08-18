import os
import subprocess

from ipwatch.analysis.passes.util import write_flows


def inbound_only(target, args):
    print("Filtering to inbound traffic")
    subprocess.check_output(["rm", "-rf", os.path.join(target, "inbound_only")])
    os.makedirs(os.path.join(target, "inbound_only"), exist_ok=True)
    subprocess.check_output(
        [
            "snort",
            "-r",
            os.path.join(target, "fetch_pcaps", "all.pcap"),
            "-c",
            os.path.join(os.path.dirname(__file__), "snort", "snort.conf"),
            "-l",
            os.path.join(target, "inbound_only"),
        ],
        stderr=subprocess.DEVNULL,
    )
    subprocess.check_output(
        f'mv {os.path.join(target, "inbound_only", "inbound.pcap.*")} {os.path.join(target, "inbound_only", "filtered.pcap")}',
        shell=True,
    )

    print("Performing ip/port statistics")
    write_flows(
        os.path.join(target, "inbound_only", "filtered.pcap"),
        os.path.join(target, "inbound_only", ""),
    )
