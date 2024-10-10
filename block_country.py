#!/usr/bin/env nix-shell
#!nix-shell -i python3 -p "python3.withPackages(ps: [ ps.tqdm ps.requests ])"
###!/usr/bin/env python3
import argparse
from subprocess import run
from ipaddress import ip_network
from sys import exit

import requests
from tqdm import tqdm

ap = argparse.ArgumentParser()
ap.add_argument("-b", "--ban", help="country codes to ban", nargs="+")
ap.add_argument("-u", "--unban", help="country codes to unban", nargs="+")
args = ap.parse_args()

if args.ban and args.unban:
    print("please specify either --ban or --unban, not both")
    exit(1)

if not args.ban and not args.unban:
    print("please specify either --ban or --unban")
    exit(1)

def valid_net(network_str):
  try:
    ip_network(network_str)
    return True
  except ValueError:
    return False

def ipset_get_existing(set_name):
    existing_cmd = run(["sudo", "ipset", "list", set_name], capture_output=True, text=True)
    if existing_cmd.returncode != 0:
        print(f"{set_name} does not exist, creating ...")
        if "_v4" in set_name:
            run(["sudo", "ipset", "create", set_name, "hash:net", "family", "inet"])
        elif "_v6" in set_name:
            run(["sudo", "ipset", "create", set_name, "hash:net", "family", "inet6"])
        existing = set()
    else:
        existing_lines = existing_cmd.stdout.split("\n")
        existing = { line.strip() for line in existing_lines if valid_net(line.strip()) }
    return existing

def add_to_ipset(set_name, response):
    existing = ipset_get_existing(set_name)
    print(f"adding {set_name} zone to ipset ...")
    for byte_line in tqdm(response.content.splitlines()):
        ip_net = byte_line.decode("utf-8").strip()
        if valid_net(ip_net) and ip_net not in existing:
            run(["sudo", "ipset", "add", set_name, ip_net])

def iptables_rule_exists(rule, ip_ver):
    if ip_ver == 4:
        result = run(f"sudo iptables --check {rule}", shell=True, capture_output=True)
    elif ip_ver == 6:
        result = run(f"sudo ip6tables --check {rule}", shell=True, capture_output=True)
    return result.returncode == 0

print("getting sudo rights (needed for ipset and iptables) ...")
run(["sudo", "true"])

if args.ban:
    for cc_input in args.ban:
        cc = cc_input.lower()
        print(f"downloading {cc} zones ...")
        r_4 = requests.get(f"https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone")
        r_6 = requests.get(f"https://www.ipdeny.com/ipv6/ipaddresses/blocks/{cc}.zone")
        if r_4.status_code != 200:
            print(f"error downloading {cc} v4 zone, ipdeny.com returned http {r_4.status_code}")
            continue
        if r_6.status_code != 200:
            print(f"error downloading {cc} v6 zone, ipdeny.com returned http {r_6.status_code}")
            continue
     
        add_to_ipset(f"{cc}_v4", r_4)
        add_to_ipset(f"{cc}_v6", r_6)

        if not iptables_rule_exists(f"INPUT -p all -m set --match-set {cc}_v4 src -j DROP", 4):
            print(f"adding iptables rule for {cc} ...")
            run(["sudo", "iptables", "-I", "INPUT", "-p", "all", "-m", "set", "--match-set", f"{cc}_v4", "src", "-j", "DROP"])
        if not iptables_rule_exists(f"INPUT -p all -m set --match-set {cc}_v6 src -j DROP", 6):
            print(f"adding ip6tables rule for {cc} ...")
            run(["sudo", "ip6tables", "-I", "INPUT", "-p", "all", "-m", "set", "--match-set", f"{cc}_v6", "src", "-j", "DROP"])

if args.unban:
    for cc_input in args.unban:
        cc = cc_input.lower()
        print(f"removing iptables rules for {cc} ...")
        run(["sudo", "iptables", "-D", "INPUT", "-p", "all", "-m", "set", "--match-set", f"{cc}_v4", "src", "-j", "DROP"])
        run(["sudo", "ip6tables", "-D", "INPUT", "-p", "all", "-m", "set", "--match-set", f"{cc}_v6", "src", "-j", "DROP"])
        print(f"removing {cc} zones from ipset ...")
        run(["sudo", "ipset", "destroy", f"{cc}_v4"])
        run(["sudo", "ipset", "destroy", f"{cc}_v6"])

