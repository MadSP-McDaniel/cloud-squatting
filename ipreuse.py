import argparse
import os
from multiprocessing.dummy import Pool

from ipwatch.analysis import pcap_analysis

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title="subcommands")

    parser_pcap_analysis = subparsers.add_parser("analysis", help="analyze pcaps")
    parser_pcap_analysis.set_defaults(func=pcap_analysis)
    parser_pcap_analysis.add_argument("--dir", default=os.path.abspath("analysis"))
    parser_pcap_analysis.add_argument("--pass", action="append")

    parser.set_defaults(func=lambda x: parser.print_help())

    args = parser.parse_args()
    args.func(args)
