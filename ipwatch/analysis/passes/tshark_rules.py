import os
import subprocess

from ipwatch.analysis.passes.util import is_local, write_flows
from ipwatch.analysis.passes.util.blocklist import blocklist

# Any packets matching these rules ban all traffic from the IP
IP_RULES = {
    "exploits": [
        "tcp.flags==0x002&&tcp.dstport==5555",  # Shellcode spam
        "dnp3",  # SCADA spam
        "tds",  # SQL Server spam
        # Shellcode spam
        'tcp.payload contains "wget"',
        'tcp.payload contains "curl"',
        'tcp.payload contains "chmod"',
        'tcp.payload contains "curl"',
        'tcp.payload contains "shell"',
    ],
    "p2p": [
        "bittorrent",
        "bitcoin||(tcp.flags==0x002&&tcp.dstport==31000)",
        "tcp.flags==0x002&&tcp.dstport==18080",  # Monero
        "tcp.flags==0x002&&tcp.dstport==22566",  # Lynx
        "tcp.flags==0x002&&tcp.dstport==30303",  # Ethereum
        "tcp.flags==0x002&&tcp.dstport==11625",  # Ethereum
        "tcp.flags==0x002&&tcp.dstport==8545",  # Crypto RPC
        "tcp.flags==0x002&&tcp.dstport==9500",  # Crypto RPC
        "tcp.flags==0x002&&tcp.dstport==9500",  # NYZO?
        "tcp.flags==0x002&&tcp.dstport==21337",  # Random crypto port
        "tcp.payload contains 76:65:72:73:69:6f:6e:00:00:00:00:00",  # P2P cryptocurrency
        "tcp.flags==0x002&&tcp.dstport==8061",  # Skype?
        'tcp.payload contains "/multistream/"',  # IPFS
    ],
    "proxy": [
        'http.request.method == "CONNECT"',  # SOCKS Proxy
        'http.request.uri matches "^https?://.*"',  # HTTP Proxy
    ],
    "health_checks": [
        'http.user_agent contains "Amazon-Route53-Health-Check-Service"',
    ],
}

PACKET_RULES = [
    # TCP artifacts
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.retransmission",
]


def tshark_rules(target, args):
    print("Filtering out IPs matching tshark rules")

    subprocess.check_output(["rm", "-rf", os.path.join(target, "tshark_rules")])
    os.makedirs(os.path.join(target, "tshark_rules"), exist_ok=True)

    last_file = os.path.join(target, "snort_rules", "filtered.pcap")

    for name, filters in IP_RULES.items():
        print(f"Running filter {name}")
        filtered_ips = set()

        # Also run basic tshark filters
        with subprocess.Popen(
            [
                "tshark",
                "-r",
                last_file,
                "-Y",
                "||".join(f"({rule})" for rule in filters),
                "-T",
                "fields",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
            ],
            stdout=subprocess.PIPE,
        ) as proc:
            for line in proc.stdout:
                if not line.strip():
                    continue
                for ip in line.decode().split():
                    if not is_local(ip):
                        filtered_ips.add(ip)

        print(f"{name} filtered {len(filtered_ips)} ips")

        blocklist(
            last_file,
            os.path.join(target, "tshark_rules", f"filtered_{name}.pcap"),
            os.path.join(target, "tshark_rules", "tmp"),
            "\n".join(filtered_ips),
        )

        write_flows(
            os.path.join(target, "tshark_rules", f"filtered_{name}.pcap"),
            os.path.join(target, "tshark_rules", f"{name}_"),
        )

        last_file = os.path.join(target, "tshark_rules", f"filtered_{name}.pcap")

    subprocess.check_output(
        [
            "tshark",
            "-r",
            last_file,
            "-Y",
            "&&".join(f"!({rule})" for rule in PACKET_RULES),
            "-w",
            os.path.join(target, "tshark_rules", "filtered.pcap"),
        ]
    )

    write_flows(
        os.path.join(target, "tshark_rules", "filtered.pcap"),
        os.path.join(target, "tshark_rules", ""),
    )
