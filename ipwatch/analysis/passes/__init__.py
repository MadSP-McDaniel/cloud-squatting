from ipwatch.analysis.passes.aws_traffic import aws_traffic, aws_not_ec2
from ipwatch.analysis.passes.blocklists import blocklists
from ipwatch.analysis.passes.fetch_pcaps import fetch_pcaps, aws_pcaps
from ipwatch.analysis.passes.figures import figures
from ipwatch.analysis.passes.inbound_only import inbound_only
from ipwatch.analysis.passes.no_dups import no_dups
from ipwatch.analysis.passes.payload import ack, http, payload
from ipwatch.analysis.passes.snort_rules import snort_rules
from ipwatch.analysis.passes.tshark_rules import tshark_rules
from ipwatch.analysis.passes.capture_stats import capture_stats

pass_funcs = {
    "aws_pcaps": aws_pcaps,
    "fetch_pcaps": fetch_pcaps,
    "inbound_only": inbound_only,
    "no_dups": no_dups,
    "payload": payload,
    "ack": ack,
    "snort_rules": snort_rules,
    "tshark_rules": tshark_rules,
    "aws_traffic": aws_traffic,
    "aws_not_ec2": aws_not_ec2,
    "blocklists": blocklists,
    "capture_stats": capture_stats,
    "figures": figures,
    "http": http,
}
