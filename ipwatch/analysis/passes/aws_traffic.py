import os
import subprocess

import requests
from ipwatch.analysis.passes.util import is_local, write_flows
from ipwatch.analysis.passes.util import allowlist


def aws_traffic(target, args):

    os.makedirs(os.path.join(target, "aws_traffic"), exist_ok=True)

    ip_ranges = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json").json()

    aws_ips = [prefix["ip_prefix"] for prefix in ip_ranges["prefixes"]]

    print(aws_ips)

    filter_str = "||".join(f"ip.addr=={ip}" for ip in aws_ips)

    subprocess.check_output(
        f'tshark -r {os.path.join(target, "snort_rules", "filtered.pcap")} -Y "{filter_str}" -w {os.path.join(target, "aws_traffic", "aws.pcap")}',
        shell=True,
    )


# This will isolate non-EC2 AWS traffic
def aws_not_ec2(target, args):

    os.makedirs(os.path.join(target, "aws_non_ec2"), exist_ok=True)

    ip_ranges = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json").json()

    aws_ips = [
        prefix["ip_prefix"]
        for prefix in ip_ranges["prefixes"]
        if prefix["service"] not in ("EC2",)
    ]

    allowlist.allowlist(
        os.path.join(target, "inbound_only", "filtered.pcap"),
        os.path.join(target, "aws_non_ec2", "filtered.pcap"),
        os.path.join(target, "aws_non_ec2", "tmp"),
        "\n".join(aws_ips),
    )
    print("Performing ip/port statistics")
    write_flows(
        os.path.join(target, "aws_non_ec2", "filtered.pcap"),
        os.path.join(target, "aws_non_ec2", ""),
    )

    subprocess.check_output(
        f'tshark -r {os.path.join(target, "aws_non_ec2", "filtered.pcap")} -Y \'http.user_agent contains "Amazon-Route53-Health-Check-Service"\' -w {os.path.join(target, "aws_non_ec2", "route53.pcap")}',
        shell=True,
    )

    write_flows(
        os.path.join(target, "aws_non_ec2", "route53.pcap"),
        os.path.join(target, "aws_non_ec2", "route53_"),
    )

    subprocess.check_output(
        f'tshark -r {os.path.join(target, "aws_non_ec2", "filtered.pcap")} -Y \'http.user_agent contains "Amazon CloudFront"\' -w {os.path.join(target, "aws_non_ec2", "cloudfront.pcap")}',
        shell=True,
    )

    write_flows(
        os.path.join(target, "aws_non_ec2", "cloudfront.pcap"),
        os.path.join(target, "aws_non_ec2", "cloudfront_"),
    )

    subprocess.check_output(
        f'tshark -r {os.path.join(target, "aws_non_ec2", "filtered.pcap")} -Y \'http.user_agent contains "Amazon Simple Notification Service Agent"\' -w {os.path.join(target, "aws_non_ec2", "sns.pcap")}',
        shell=True,
    )

    write_flows(
        os.path.join(target, "aws_non_ec2", "sns.pcap"),
        os.path.join(target, "aws_non_ec2", "sns_"),
    )
