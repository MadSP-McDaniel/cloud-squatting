from ipwatch.analysis.passes import pass_funcs


def pcap_analysis(args):
    target = args.dir
    passes = getattr(args, "pass")
    if not passes:
        passes = [
            "inbound_only",
            "blocklists",
            "no_dups",
            "ack",
            "payload",
            "snort_rules",
            "tshark_rules",
            "aws_traffic",
            "http",
        ]
    for passname in passes:
        print(f"Running pass {passname}")
        pass_funcs[passname](target, args)
