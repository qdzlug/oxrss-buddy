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
    try:
        config = {}

        zone = questionary.text("External DNS zone name (e.g. oxide.example.com)").ask()
        if zone is None:
            sys.exit("❌ No zone name provided.")
        config["external_dns_zone_name"] = zone

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

        # Allowed source IPs for user-facing services
        config["allowed_source_ips"] = {}

        allow_all = questionary.confirm("Allow access from any IP address?").ask()
        if allow_all:
            config["allowed_source_ips"]["allow"] = "any"
        else:
            config["allowed_source_ips"]["allow"] = "list"
            while True:
                cidrs = parse_comma_list("Enter CIDRs to allow (e.g. 1.2.3.4/32, 10.0.0.0/8)")
                try:
                    for cidr in cidrs:
                        ip_network(cidr, strict=False)
                    config["allowed_source_ips"]["ips"] = cidrs
                    break
                except ValueError:
                    print("❌ One or more entries are not valid CIDRs. Try again.")

        # Infrastructure IP range
        while True:
            infra_first = questionary.text("First infrastructure IP address").ask()
            infra_last = questionary.text("Last infrastructure IP address").ask()
            try:
                ip_address(infra_first)
                ip_address(infra_last)
                config.setdefault("rack_network_config", {})
                config["rack_network_config"]["infra_ip_first"] = infra_first
                config["rack_network_config"]["infra_ip_last"] = infra_last
                break
            except ValueError:
                print("❌ One or both IPs are invalid. Please re-enter.")

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
                print(f"❌ Invalid sleds: {bad}. Sleds must be in range 0–31. Please try again.")
                continue
            config["bootstrap_sleds"] = all_sleds
            break

        config.setdefault("rack_network_config", {})["bgp"] = []
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
                    ip_network(p, strict=False)
            except ValueError:
                print("❌ One or more BGP prefixes are invalid CIDRs. Try again.")
                continue
            config["rack_network_config"]["bgp"].append({"asn": asn, "originate": prefixes})

        # --- Switch Port Configuration ---
        config["rack_network_config"].setdefault("switch_ports", {})

        while questionary.confirm("Configure a switch port?").ask():
            port_full = questionary.text("Switch port name (e.g. switch0.qsfp0)").ask()
            if not port_full or "." not in port_full:
                print("❌ Invalid format. Must be like switch0.qsfp0")
                continue
            switch_name, port_name = port_full.split(".", 1)

            # CIDR for the address
            address = questionary.text(f"IP address for {port_full} (CIDR format)").ask()
            try:
                ip_network(address, strict=False)
            except ValueError:
                print("❌ Invalid CIDR.")
                continue

            # Optional speed
            speed = questionary.text("Port speed (optional, e.g. speed100_g)").ask() or ""

            # Autonegotiation
            autoneg = questionary.confirm("Enable autonegotiation?").ask()

            # Optional BGP peer
            bgp_peer = {}
            if questionary.confirm("Add BGP peer on this port?").ask():
                try:
                    asn = int(questionary.text("ASN for BGP peer").ask())
                    addr = questionary.text("BGP peer IP address").ask()
                    ip_address(addr)
                    bgp_peer = {
                        "asn": asn,
                        "port": port_name,
                        "addr": addr,
                        "hold_time": 180,
                        "idle_hold_time": 3,
                        "delay_open": 0,
                        "connect_retry": 3,
                        "keepalive": 60,
                        "enforce_first_as": False,
                        "remote_asn": 65197
                    }
                except Exception as e:
                    print(f"❌ Error in BGP peer config: {e}")
                    continue

            # Set data structure
            switch_block = config["rack_network_config"].setdefault(switch_name, {})
            port_block = switch_block.setdefault(port_name, {
                "routes": [],
                "addresses": [],
                "uplink_port_speed": "",
                "uplink_port_fec": "",
                "autoneg": False
            })
            port_block["addresses"] = [address]
            port_block["uplink_port_speed"] = speed
            port_block["autoneg"] = autoneg

            if bgp_peer:
                port_block.setdefault("bgp_peers", []).append(bgp_peer)

        output = questionary.text("Write config to file (or '-' for stdout)?").ask()
        try:
            if output in ("-", "stdout"):
                buf = io.BytesIO()
                tomli_w.dump(config, buf)
                print(buf.getvalue().decode())
            else:
                with open(output, "wb") as f:
                    tomli_w.dump(config, f)
                print(f"Config written to {output}")
        except Exception as e:
            print(f"❌ Failed to write config: {e}")
            sys.exit(2)

        return config

    except KeyboardInterrupt:
        print("\n❌ User interrupted. Exiting.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")
        sys.exit(2)


def generate_config_main():
    return generate_config()


if __name__ == "__main__":
    generate_config()
