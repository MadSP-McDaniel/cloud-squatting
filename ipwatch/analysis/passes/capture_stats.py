import os
import ujson as json
import csv
import matplotlib.pyplot as plt
import ipaddress
import dateutil
from collections import Counter
from rpy2.robjects.packages import importr
from rpy2 import robjects
import operator
from functools import reduce, lru_cache
import datetime
from multiprocessing import Pool
import time
import textwrap

MIN_DATE = dateutil.parser.parse("2000-01-01 0:0:00 UTC").timestamp()


def aws_prefixes():
    with open(os.path.join(os.path.dirname(__file__), "ip-ranges.json")) as f:
        prefixes = json.load(f)["prefixes"]
        prefixes = [
            ipaddress.ip_network(prefix["ip_prefix"])
            for prefix in prefixes
            if prefix["region"] == "us-east-1"
            and (prefix["service"] in ("EC2", "EC2_INSTANCE_CONNECT"))
        ]
    return prefixes


def top_million():
    ranks = {}

    with open(os.path.join(os.path.dirname(__file__), "majestic_million.csv")) as f:
        for row in csv.DictReader(f):
            ranks[row["Domain"]] = int(row["GlobalRank"])
    del ranks["com.br"]
    del ranks["co.uk"]
    return ranks


def valid(meta):
    if not meta["PublicIp"]:
        return False
    if not meta["Zone"]:
        return False
    if meta["LaunchTime"].year < 2000:
        return False
    return True


def load_meta(i):
    if not os.path.isdir(i):
        return None
    if not os.path.exists(os.path.join(i, "meta")):
        return None
    if not os.path.exists(os.path.join(i, "requests")):
        return None
    with open(os.path.join(i, "meta")) as w:
        meta = json.load(w)
    meta["LaunchTime"] = dateutil.parser.parse(meta["LaunchTime"])
    meta["RecordStartTime"] = dateutil.parser.parse(meta["RecordStartTime"])
    if not valid(meta):
        return None
    return meta


def experiment_range(target):
    with open(os.join(target, "experiment_range"), "w") as f:
        print("Loading metas")
        start = min(meta["LaunchTime"] for meta in metas())
        end = max(meta["LaunchTime"] for meta in metas())

        print("Experiment start", start, file=f)
        print("Experiment end", end, file=f)


def reuse_interval(target):
    ip_metas = {}
    ip_releases = {}
    for meta in metas():
        ip_metas.setdefault(meta["PublicIp"], set()).add(meta["LaunchTime"])
        ip_releases.setdefault(meta["PublicIp"], set()).add(
            meta["RecordStartTime"]
            + datetime.timedelta(seconds=meta["TargetRecordDuration"])
        )

    durations = []

    for ip, launches in ip_metas.items():
        if len(launches) < 2:
            continue
        launches = list(sorted(launches))
        releases = list(sorted(ip_releases[ip]))
        durations.extend(
            (launches[i + 1] - releases[i]).total_seconds()
            for i in range(len(launches) - 1)
        )

    plt.hist([d / 3600 for d in durations], bins=100)
    plt.xlabel("Time before reuse (hours)")
    plt.ylabel("Number of instances")
    plt.savefig(os.join(target, "reuse_histogram_all.pdf"))
    plt.clf()

    plt.hist([d / 3600 for d in durations if d < 3600 * 24], bins=24 * 4)
    plt.xlabel("Time before reuse (hours)")
    plt.ylabel("Number of instances")
    plt.savefig(os.join(target, "reuse_histogram_24h.pdf"))
    plt.clf()

    plt.hist([d / 3600 for d in durations if d < 3600 * 6], bins=60)
    plt.xlim(0, 6)
    plt.axvline(
        min(durations) / 3600,
        color="k",
        linestyle="dashed",
        linewidth=1,
        label=f"{min(durations)/60} min",
    )
    plt.xlabel("Time before reuse (hours)")
    plt.ylabel("Number of instances")
    plt.savefig(os.join(target, "reuse_histogram_6h.pdf"))
    plt.clf()


@lru_cache(1)
def metas(path):
    print("Loading metas")
    count = 0
    items = []

    p = Pool(16)
    start = time.time()

    items = [meta for meta in p.map(load_meta, os.listdir(path)) if meta is not None]

    print(f"Loaded {len(items)} items in {time.time()-start}s")
    return items


def zone_stats(target):
    with open(os.join(target, "zone_stats"), "w") as f:
        count = 0
        # Sightings are pairs of (IP, datetime) when IPs are seen
        zone_sightings = {}
        ip_zones = {}

        read_metas = metas(os.path.join(target, "aws-pcaps"))

        for meta in read_metas:
            zone_sightings.setdefault(meta["Zone"], []).append(
                (meta["PublicIp"], meta["LaunchTime"])
            )
            ip_zones.setdefault(meta["PublicIp"], set()).add(meta["Zone"])

        print(
            "Number of zones per IP:",
            Counter(len(zones) for zones in ip_zones.values()),
            file=f,
        )

        servers_sum = 0
        uniques_sum = 0
        closed_sum = 0
        open_sum = 0
        R_per_hour_sum = 0
        A_per_hour_sum = 0

        for zone, sightings in sorted(zone_sightings.items()):

            ### CLOSED MODEL
            # Count the number of times each IP was seen
            ip_counts = Counter([s[0] for s in sightings])
            # Count the number of times each count was seen
            reuse_counts = Counter(ip_counts.values())
            # print(key, reuse_counts)
            Rcapture = importr("Rcapture")
            m = robjects.r["matrix"](
                robjects.IntVector(
                    list(reuse_counts.keys()) + list(reuse_counts.values())
                ),
                nrow=len(reuse_counts),
            )
            closed_pop = int(
                Rcapture.closedpCI_0(
                    m, dtype="nbcap", dfreq=True, t=float("inf"), m="Mh"
                )[8][0]
            )

            ### OPEN MODEL

            # Bucket the sightings into discrete weeks
            start = min(s[1] for s in sightings)
            end = max(s[1] for s in sightings)
            buckets = 10
            interval = (end - start) / buckets
            interval_seconds = interval.days * 86400 + interval.seconds

            ip_sightings = {}
            ip_sighting_counts = Counter()
            # Each record is whether or not the IP was seen in a given week
            for sighting in sightings:
                bucket = (sighting[1] - start) // interval
                if bucket == buckets:
                    bucket -= 1
                # print(bucket)
                record = ip_sightings.setdefault(sighting[0], [0] * buckets)
                record[bucket] = 1
                ip_sighting_counts[sighting[0]] += 1
            # Convert records into frequencies of each type of record
            c = Counter(tuple(t) for t in ip_sightings.values())
            entries = reduce(operator.add, [k + (v,) for k, v in c.items()])
            # print(zone)
            base = importr("base")
            m = base.matrix(
                robjects.IntVector(entries),
                ncol=buckets
                + 1,  # Really this is (buckets-1) + a column for the frequency
                byrow=True,
            )
            Rcapture = importr("Rcapture")
            # dfreq means to use the frequencies that we computed.
            results = Rcapture.openp(m, dfreq=True, m="ep")
            # print(textwrap.indent(str(results), "\t"))
            open_pop = int(results[8][0])
            R = results[7][1 : buckets - 2]
            abundances = results[6][1 : buckets - 2]
            survivals = results[5][0 : buckets - 3]
            A_per_hour = sum(
                abundances[i] * (1 - survivals[i]) for i in range(len(abundances))
            ) / (len(abundances) * interval_seconds / 3600)
            # print(R)
            S = results[5][1 : buckets - 2]
            R_per_hour = sum(R) / (len(R) * interval_seconds / 3600)
            servers = len(sightings)
            unique_ips = len(ip_counts)
            detection_rate = round(unique_ips / open_pop * 100)

            sik = lambda x: f"$\\SI{{{round(x/1000)}}}{{k}}$"

            servers_sum += servers
            uniques_sum += unique_ips
            closed_sum += closed_pop
            open_sum += open_pop
            R_per_hour_sum += R_per_hour
            A_per_hour_sum += A_per_hour

            print(
                zone,
                sik(servers),
                sik(unique_ips),
                sik(closed_pop),
                sik(open_pop),
                f"$\\SI{{{round(R_per_hour)}}}{{/h}}$",
                f"$\\SI{{{round(A_per_hour)}}}{{/h}}$",
                f"$\\SI{{{round(detection_rate)}}}{{\\%}}$",
                sep=" & ",
                end=" \\\\\n",
                file=f,
            )

            # import pdb

            # pdb.set_trace()

            # print(Rcapture.openp(m, dfreq=True))

        print("\\hline", file=f)
        print(
            "Total",
            sik(servers_sum),
            sik(uniques_sum),
            sik(closed_sum),
            sik(open_sum),
            f"$\\SI{{{round(R_per_hour_sum)}}}{{/h}}$",
            f"$\\SI{{{round(A_per_hour_sum)}}}{{/h}}$",
            f"$\\SI{{{round(round(uniques_sum / open_sum * 100))}}}{{\\%}}$",
            sep=" & ",
            end=" \\\\\n",
            file=f,
        )

def main(target):
    with open(os.join(target, "zone_stats"), "w") as f:
        prefixes = aws_prefixes()
        ranks = top_million()
        prefix_zones = {prefix: set() for prefix in prefixes}

        totals = Counter()

        hosts = {}
        createds = {}
        first_seens = {}
        zones = {}
        types = {}
        r53s = {}
        metas = []
        ips = {}
        host_counts = Counter()

        count = 0

        for i in os.listdir():
            count += 1
            if count % 1000 == 0:
                print(count)
            if not os.path.isdir(i):
                continue
            if not os.path.exists(os.path.join(i, "meta")):
                continue
            if not os.path.exists(os.path.join(i, "requests")):
                continue
            # print(i)
            with open(os.path.join(i, "meta")) as w:
                meta = json.load(w)
            zones.setdefault(meta["PublicIp"], set()).add(meta["Zone"])
            if meta["PublicIp"]:
                parsed = ipaddress.ip_address(meta["PublicIp"])
                prefix = next(prefix for prefix in prefixes if parsed in prefix)
                prefix_zones[prefix].add(meta["Zone"])
            metas.append(meta)
            types.setdefault(meta["PublicIp"], set()).add(meta["InstanceType"])
            requests = []
            with open(os.path.join(i, "requests")) as w:
                requests = list(map(json.loads, w))
            for request in requests:
                totals["reqs"] += 1
                r53s.setdefault(request["hostname"], set()).add(
                    "Route53" in str(request.get("meta"))
                )
                if isinstance(request["nslookup_ip"], list):
                    if ".compute-1.amazonaws.com" in request["hostname"]:
                        continue
                    if meta["PublicIp"] in request["nslookup_ip"]:
                        totals["valid"] += 1

                        hosts[request["hostname"]] = request
                        host_counts[request["hostname"]] += 1
                        ips[request["hostname"]] = meta["PublicIp"]
                        first_seens[request["hostname"]] = (
                            min(request["created_at"], first_seens[request["hostname"]])
                            if request["hostname"] in first_seens
                            else request["created_at"]
                        )
                        createds[request["hostname"]] = (
                            min(meta["RecordStartTime"], createds[request["hostname"]])
                            if request["hostname"] in createds
                            else meta["RecordStartTime"]
                        )
                        # print(i, "\t", request, request["created_at"])
                        break

        print("Prefix Zones", prefix_zones, file=f)
        print(
            "Available IPs:",
            sum(
                prefix.num_addresses
                for prefix, zones in prefix_zones.items()
                if len(zones) > 0
            ),
            sum(prefix.num_addresses for prefix, zones in prefix_zones.items()),
            file=f,
        )

        print("Starting plots")

        # First seen histogram

        seen_durations = []
        for k in first_seens.keys():
            v1 = dateutil.parser.parse(first_seens[k])
            v2 = dateutil.parser.parse(createds[k])
            #print(v1 - v2)
            seen_durations.append((v1 - v2).seconds)

        plt.hist(seen_durations, cumulative=True, bins=1000)
        plt.xlabel("Time until domain discovery")
        plt.ylabel("Fraction of domains")
        plt.savefig(os.join(target, "discovery_histogram.pdf"))
        plt.clf()

        ips_found = {}
        total_ips = {}
        global_ips = []
        averaged = {}
        times = {}

        for meta in sorted(metas, key=lambda meta: meta["LaunchTime"]):
            zone = meta["Zone"]
            times.setdefault(zone, []).append(dateutil.parser.parse(meta["LaunchTime"]))
            ips_found.setdefault(zone, set()).add(meta["PublicIp"])
            total_ips.setdefault(zone, []).append(len(ips_found[zone]))
            global_ips.append(sum(len(v) for v in ips_found.values()))
            if len(total_ips[zone]) > 1000:
                averaged.setdefault(zone, []).append(
                    total_ips[zone][-1] - total_ips[zone][-1001]
                )

        plt.plot(range(len(global_ips)), global_ips, label="Actual")
        plt.plot(range(len(global_ips)), range(len(global_ips)), label="Ideal")
        plt.xlabel("Hosts provisioned")
        plt.ylabel("IPs discovered")
        plt.legend()
        plt.savefig(os.join(target, "ips.pdf"))
        plt.clf()

        for zone, average in averaged.items():
            plt.plot(range(1000, len(average) + 1000), average, label=zone)
        plt.xlabel("Hosts provisioned")
        plt.ylabel("IP Yield")
        plt.legend()
        plt.savefig(os.join(target, "yield.pdf"))
        plt.clf()

        for zone, t in times.items():
            plt.plot(t, range(len(t)), label=zone)
        plt.xlabel("Time")
        plt.ylabel("Hosts created")
        plt.legend()
        plt.savefig(os.join(target, "created.pdf"))

        def rank(name):
            parts = name.split(".")
            r = 1000000
            for i in range(1, len(parts)):
                subname = ".".join(parts[-i:])
                r = min(r, ranks.get(subname.lower(), 1000000))
            return r

        def tld(name):
            parts = name.split(".")
            r = 1000000
            # Look at longest domains first
            for i in range(0, len(parts)):
                subname = ".".join(parts[i:])
                if subname.lower() in ranks:
                    return subname.lower()
            return ""

        print("Dup zones:", [(ip, v) for ip, v in zones.items() if len(v) > 1], file=f)
        print("Dup types:", len([(ip, v) for ip, v in types.items() if len(v) > 1]), file=f)

        for host in sorted(hosts.values(), key=lambda host: rank(host["hostname"])):
            # if rank(host["hostname"]) >= 1000000:
            #    continue
            # totals["significant"] += host_counts[host["hostname"]]
            print(
                host["created_at"],
                rank(host["hostname"]),
                ips[host["hostname"]],
                host["hostname"],
                tld(host["hostname"]),
                r53s.get(host["hostname"]),
                file=f
            )

        #print(totals)


def capture_stats(target, args):
    os.makedirs(os.path.join(target, "capture_stats"), exist_ok=True)
    reuse_interval(os.path.join(target, "capture_stats"))
    experiment_range(os.path.join(target, "capture_stats"))
    zone_stats(os.path.join(target, "capture_stats"))
    main(os.path.join(target, "capture_stats"))
