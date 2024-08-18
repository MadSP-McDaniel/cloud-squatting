import os
import shutil
import subprocess
from multiprocessing.dummy import Pool

from ipwatch.analysis.passes.util import is_local, write_flows
from ipwatch.analysis.passes.util.blocklist import blocklist
from ipwatch.analysis.passes.util import mergecap


def filter_stream_bpf(source, target, filter):
    shutil.rmtree(os.path.join(target), ignore_errors=True)

    os.makedirs(os.path.join(target, "split"), exist_ok=True)
    os.makedirs(os.path.join(target, "filtered"), exist_ok=True)

    subprocess.check_call(
        f'PcapSplitter -f {source} -o {os.path.join(target, "split")} -m connection -p 10000',
        shell=True,
    )

    stream_tasks = [
        (
            os.path.join(target, "split", name),
            os.path.join(target, "filtered", name),
        )
        for name in os.listdir(os.path.join(target, "split"))
    ]

    print(f"Performing {len(stream_tasks)} filter tasks")

    p = Pool(24)

    def filter_stream(x):
        infile, outfile = x

        streams = set()
        with subprocess.Popen(
            f"tshark -r {infile} -Y '{filter}' -T fields -e tcp.stream",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ) as proc:
            for line in proc.stdout:
                if not line.strip():
                    continue
                streams.add(line.strip().decode())
        filter_str = "||".join(f"tcp.stream=={stream}" for stream in streams)
        subprocess.check_output(
            f"tshark -r {infile} -Y '{filter_str}' -w {outfile}",
            shell=True,
            stderr=subprocess.DEVNULL,
        )

    p.map(filter_stream, stream_tasks, 1)

    print("Merging captures")

    mergecap(
        os.path.join(target, "filtered", "*"),
        os.path.join(target, "filtered.pcap"),
    )


# Only keep TCP flows with client ACK
def ack(target, args):
    filter_stream_bpf(
        os.path.join(target, "no_dups", "filtered.pcap"),
        os.path.join(target, "ack"),
        "tcp.flags == 0x010",
    )
    write_flows(
        os.path.join(target, "ack", "filtered.pcap"),
        os.path.join(target, "ack", ""),
    )


# Only keep TCP flows with payloads
def payload(target, args):

    filter_stream_bpf(
        os.path.join(target, "ack", "filtered.pcap"),
        os.path.join(target, "payload"),
        "tcp.payload",
    )
    write_flows(
        os.path.join(target, "payload", "filtered.pcap"),
        os.path.join(target, "payload", ""),
    )


def http(target, args):
    filter_stream_bpf(
        os.path.join(target, "tshark_rules", "filtered.pcap"),
        os.path.join(target, "http"),
        "http",
    )
    write_flows(
        os.path.join(target, "http", "filtered.pcap"),
        os.path.join(target, "http", ""),
    )
