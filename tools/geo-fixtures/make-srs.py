#!/usr/bin/env python3
"""Compiles test rule-sets with a real sing-box and records which queries
sing-box itself says match, for the .srs reader in crates/sybau-route.

    make-srs.py <sing-box binary> <output dir>
"""
import json
import os
import subprocess
import sys

SINGBOX, OUT = sys.argv[1], sys.argv[2]

RULES = [
    {"domain": ["full.example.com", "Mixed.Case.Example"], "domain_suffix": ["suffix.example.org", ".sub-only.net", "co.uk"]},
    {"domain_keyword": ["kw-hit"]},
    {"domain_regex": [r"^r[0-9]+\.regex\.test$"]},
    {"ip_cidr": ["10.0.0.0/8", "172.16.0.0/12", "2001:db8::/32", "198.51.100.7"]},
    {"type": "logical", "mode": "and", "rules": [{"domain_suffix": ["and.test"]}, {"domain_keyword": ["yes"]}]},
    {"domain_suffix": ["inverted.test"], "invert": True},
    {"port": [443], "port_range": ["1000:2000"], "network": ["udp"], "process_name": ["Discord.exe"],
     "process_path": ["/usr/bin/curl"], "source_ip_cidr": ["192.168.0.0/16"], "domain": ["port-rule.test"]},
]
QUERIES = [
    "full.example.com", "www.full.example.com", "mixed.case.example", "suffix.example.org", "a.b.suffix.example.org",
    "xsuffix.example.org", "x.sub-only.net", "sub-only.net", "bbc.co.uk", "co.uk", "xco.uk", "aa-kw-hit.net",
    "r42.regex.test", "rr.regex.test", "yes.and.test", "no.and.test", "inverted.test", "a.inverted.test",
    "port-rule.test", "nothing.example", "10.1.2.3", "11.0.0.0", "172.31.255.255", "172.32.0.0", "2001:db8::1",
    "2001:db9::1", "198.51.100.7", "198.51.100.8",
]

expectations = []
# One rule per file: an inverted rule matches almost everything and would
# hide what the other rules do.
for version in (1, 2, 3):
    for index, rule in enumerate(RULES):
        if version == 1 and rule.get("type") == "logical":
            continue
        name = f"rs-v{version}-{index}"
        src = os.path.join(OUT, name + ".json")
        dst = os.path.join(OUT, name + ".srs")
        with open(src, "w") as f:
            json.dump({"version": version, "rules": [rule]}, f, indent=1)
        subprocess.run([SINGBOX, "rule-set", "compile", "-o", dst, src], check=True)
        os.remove(src)
        for q in QUERIES:
            r = subprocess.run([SINGBOX, "rule-set", "match", "-f", "binary", dst, q], capture_output=True, text=True, check=True)
            expectations.append({"file": name + ".srs", "query": q, "match": "match rules" in (r.stdout + r.stderr)})

with open(os.path.join(OUT, "singbox-expectations.json"), "w") as f:
    json.dump(expectations, f, indent=1)
    f.write("\n")
print(f"{sum(e['match'] for e in expectations)}/{len(expectations)} queries match")
