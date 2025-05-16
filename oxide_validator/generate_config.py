import questionary
import tomli_w
from ipaddress import ip_address


def parse_comma_list(prompt, cast=str):
    raw = questionary.text(prompt).ask()
    if not raw:
        return []
    return [cast(x.strip()) for x in raw.split(",") if x.strip()]


def parse_ip_range(prompt):
    raw = questionary.text(prompt + " (CIDR or range e.g. 10.0.0.0/24 or 10.0.0.1-10.0.0.20)").ask()
    try:
        if '/' in raw:
            from ipaddress import ip_network
            net = ip_network(raw.strip(), strict=False)
            return {"first": str(net.network_address), "last": str(net.broadcast_address)}
        else:
            first, last = map(str.strip, raw.split("-"))
            return {"first": first, "last": last}
    except Exception:
        print("Invalid range or CIDR. Try again.")
        return parse_ip_range(prompt)


def generate_config():
    config = {}

    config["external_dns_zone_name"] = questionary.text("External DNS zone name (e.g. oxide.example.com)").ask()
    while True:
        external_dns = parse_comma_list("External DNS IPs (comma separated)")
        try:
            for ip in external_dns:
                ip_address(ip)
            config["external_dns_ips"] = external_dns
            break
        except ValueError:
            print("❌ One or more external DNS IPs are invalid. Try again.")
    while True:
        ntp_servers = parse_comma_list("NTP servers (comma separated)")
        try:
            for ip in ntp_servers:
                ip_address(ip)
            config["ntp_servers"] = ntp_servers
            break
        except ValueError:
            print("❌ One or more NTP server IPs are invalid. Try again.")
    # DNS servers will be prompted after internal IP ranges
    # config["dns_servers"] = parse_comma_list("DNS servers (comma separated)")

    # IP pool ranges
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

    # Prompt for internal DNS servers after IP ranges are known
    def is_within_ranges(ip):
        target = int(ip_address(ip))
        for r in config["internal_services_ip_pool_ranges"]:
            start = int(ip_address(r['first']))
            end = int(ip_address(r['last']))
            if start <= target <= end:
                return True
        return False

    while True:
        internal_dns = parse_comma_list("Internal DNS servers (comma separated)")
        bad_ips = [ip for ip in internal_dns if not is_within_ranges(ip)]
        if bad_ips:
            print(f"❌ These internal DNS IPs are not within internal ranges: {', '.join(bad_ips)}. Try again.")
            continue
        config["dns_servers"] = internal_dns
        break


        r = parse_ip_range("Add internal service IP range")
        if overlaps(r['first'], r['last']):
            print("❌ That range overlaps with an existing pool. Try again.")
            continue
        existing_ranges.append(r)
        config["internal_services_ip_pool_ranges"].append(r)
        if not questionary.confirm("Add another range?").ask():
            break

    # Sleds
    def parse_sleds(prompt):
        raw = questionary.text(prompt + " (e.g. 1-3,5,7)").ask()
        sleds = set()
        for part in raw.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                sleds.update(range(start, end + 1))
            elif part:
                sleds.add(int(part))
        return sorted(sleds)

        # Validate sleds within 0-31
    all_sleds = parse_sleds("Bootstrap sled IDs")
    for s in all_sleds:
        if s < 0 or s > 31:
            print(f"❌ Sled {s} is out of the valid range 0–31. Aborting.")
            return
    config["bootstrap_sleds"] = all_sleds

    # BGP Configuration
    config["rack_network_config"] = {"bgp": []}
    while questionary.confirm("Add BGP peer?").ask():
        asn = questionary.text("BGP ASN (positive integer)").ask()
        try:
            asn = int(asn)
            if asn <= 0:
                raise ValueError()
        except ValueError:
            print("❌ ASN must be a positive integer.")
            continue
        prefixes = parse_comma_list("BGP prefixes (CIDRs, comma separated)")
        try:
            for p in prefixes:
                from ipaddress import ip_network
                ip_network(p, strict=False)
        except ValueError:
            print("❌ One or more BGP prefixes are invalid CIDRs. Try again.")
            continue
        config["rack_network_config"]["bgp"].append({"asn": asn, "originate": prefixes})

    # Save to file or screen
    output = questionary.text("Write config to file (or '-' for stdout)?").ask()
    if output in ("-", "stdout"):
        import sys
        tomli_w.dump(config, sys.stdout.buffer)
    else:
        with open(output, "wb") as f:
            tomli_w.dump(config, f)
        print(f"Config written to {output}")


if __name__ == "__main__":
    generate_config()
