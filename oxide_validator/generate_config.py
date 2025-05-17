import questionary
import tomli_w
import sys
import io
from ipaddress import ip_address, ip_network

def parse_comma_list(prompt, cast=str):
    raw = questionary.text(prompt).ask()
    if raw is None:
        sys.exit("❌ No input provided.")
    return [cast(x.strip()) for x in raw.split(",") if x.strip()]

def parse_ip_range(prompt):
    raw = questionary.text(prompt + " (CIDR or range e.g. 10.0.0.0/24 or 10.0.0.1-10.0.0.20)").ask()
    if raw is None:
        sys.exit("❌ No IP range provided.")
    try:
        if '/' in raw:
            net = ip_network(raw.strip(), strict=False)
            return {"first": str(net.network_address), "last": str(net.broadcast_address)}
        else:
            first, last = map(str.strip, raw.split("-"))
            return {"first": first, "last": last}
    except ValueError:
        print("Invalid range or CIDR. Try again.")
        return parse_ip_range(prompt)

def generate_config():
    config = {}

    config["external_dns_zone_name"] = questionary.text("External DNS zone name").ask()
    config["external_dns_ips"] = parse_comma_list("External DNS IPs (comma separated)")
    config["ntp_servers"] = parse_comma_list("NTP servers (comma separated)")

    config["internal_services_ip_pool_ranges"] = []
    existing_ranges = []

    def overlaps(new_first, new_last):
        new_start = int(ip_address(new_first))
        new_end = int(ip_address(new_last))
        for r in existing_ranges:
            r_start = int(ip_address(r['first']))
            r_end = int(ip_address(r['last']))
            if new_start <= r_end and new_end >= r_start:
                return True
        return False

    while True:
        r = parse_ip_range("Add internal service IP range")
        if overlaps(r['first'], r['last']):
            print("❌ That range overlaps with an existing pool. Try again.")
            continue
        existing_ranges.append(r)
        config["internal_services_ip_pool_ranges"].append(r)
        if not questionary.confirm("Add another range?").ask():
            break

    while True:
        internal_dns = parse_comma_list("Internal DNS servers (comma separated)")
        bad_ips = [ip for ip in internal_dns if not any(
            int(ip_address(r['first'])) <= int(ip_address(ip)) <= int(ip_address(r['last']))
            for r in config["internal_services_ip_pool_ranges"]
        )]
        if bad_ips:
            print(f"❌ These internal DNS IPs are not within internal ranges: {', '.join(bad_ips)}. Try again.")
            continue
        config["dns_servers"] = internal_dns
        break

    config["allowed_source_ips"] = {}
    if questionary.confirm("Allow access from any IP address?").ask():
        config["allowed_source_ips"]["allow"] = "any"
    else:
        config["allowed_source_ips"]["allow"] = "list"
        while True:
            cidrs = parse_comma_list("Enter allowed CIDRs (comma separated)")
            try:
                for cidr in cidrs:
                    ip_network(cidr, strict=False)
                config["allowed_source_ips"]["ips"] = cidrs
                break
            except ValueError:
                print("❌ One or more CIDRs are invalid. Try again.")

    config.setdefault("rack_network_config", {})
    config["rack_network_config"]["infra_ip_first"] = questionary.text("First infrastructure IP address").ask()
    config["rack_network_config"]["infra_ip_last"] = questionary.text("Last infrastructure IP address").ask()

    def parse_sleds(prompt):
        raw = questionary.text(prompt + " (e.g. 1-3,5,7)").ask()
        if raw is None:
            sys.exit("❌ No sled input provided.")
        sleds = set()
        for part in raw.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                sleds.update(range(start, end + 1))
            elif part:
                sleds.add(int(part))
        return sorted(sleds)

    while True:
        all_sleds = parse_sleds("Bootstrap sled IDs")
        bad = [s for s in all_sleds if s < 0 or s > 31]
        if bad:
            print(f"❌ Invalid sleds: {bad}. Sleds must be in range 0–31.")
            continue
        config["bootstrap_sleds"] = all_sleds
        break

    config["rack_network_config"]["bgp"] = []
    while questionary.confirm("Add BGP peer?").ask():
        asn = questionary.text("BGP ASN").ask()
        try:
            asn = int(asn)
            if asn <= 0:
                raise ValueError()
        except ValueError:
            print("❌ ASN must be a positive integer.")
            continue
        prefixes = parse_comma_list("BGP prefixes (CIDRs)")
        try:
            for p in prefixes:
                ip_network(p, strict=False)
        except ValueError:
            print("❌ Invalid prefix.")
            continue
        config["rack_network_config"]["bgp"].append({
            "asn": asn,
            "originate": prefixes
        })

    if questionary.confirm("Configure a switch port?").ask():
        config["rack_network_config"]["switch0"] = {}
        config["rack_network_config"]["switch0"]["qsfp0"] = {}
        port_cfg = config["rack_network_config"]["switch0"]["qsfp0"]
        port_cfg["addresses"] = parse_comma_list("Switch port CIDRs (e.g. 10.0.0.1/31)")
        port_cfg["autoneg"] = questionary.text("Autonegotiation? (true/false)").ask()
        port_cfg["uplink_port_speed"] = questionary.text("Port speed (e.g. speed100_g)").ask()

        if questionary.confirm("Add BGP peer to this port?").ask():
            port_cfg["bgp_peers"] = []
            peer = {
                "asn": int(questionary.text("Peer ASN").ask()),
                "port": "qsfp0",
                "addr": questionary.text("Peer IP address").ask(),
                "remote_asn": int(questionary.text("Remote ASN").ask()),
                "auth_key_id": questionary.text("Auth key ID").ask(),
                "multi_exit_discriminator": int(questionary.text("MED (optional, int)").ask() or 0),
                "communities": parse_comma_list("Communities (comma-separated integers)", int),
                "local_pref": int(questionary.text("Local pref").ask() or 0),
                "enforce_first_as": questionary.confirm("Enforce first AS?").ask(),
                "allowed_import": parse_comma_list("Allowed import prefixes (CIDRs)"),
                "allowed_export": parse_comma_list("Allowed export prefixes (CIDRs)"),
                "vlan_id": int(questionary.text("VLAN ID").ask() or 0)
            }
            port_cfg["bgp_peers"].append(peer)

    output = questionary.text("Write config to file (or '-' for stdout)?").ask()
    if output in ("-", "stdout"):
        buf = io.BytesIO()
        tomli_w.dump(config, buf)
        print(buf.getvalue().decode())
    else:
        with open(output, "wb") as f:
            tomli_w.dump(config, f)
        print(f"✅ Config written to {output}")

    return config

def generate_config_main():
    return generate_config()

if __name__ == "__main__":
    generate_config()
