import os
import shutil
import subprocess
import tempfile


def blocklist(infile, outfile, tmpdir, blocklist):
    if not tmpdir:
        tmpdir = tempfile.mkdtemp()

    print(f"Running snort in {tmpdir}")

    shutil.rmtree(tmpdir, ignore_errors=True)
    os.makedirs(tmpdir, exist_ok=True)
    shutil.copytree(
        os.path.join(os.path.dirname(__file__), "snort"), os.path.join(tmpdir, "snort")
    )

    with open(os.path.join(tmpdir, "snort", "black_list.rules"), "w") as f:
        f.write(blocklist)

    subprocess.check_output(
        [
            "snort",
            "-r",
            infile,
            "-c",
            os.path.join(tmpdir, "snort", "snort.conf"),
            "-l",
            tmpdir,
        ],
        input=blocklist.encode(),
        stderr=subprocess.DEVNULL,
    )
    subprocess.check_output(
        f"cp {os.path.join(tmpdir,'output.pcap.*')} {outfile}", shell=True
    )
