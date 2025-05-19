import argparse
import logging
import sys
import tomllib
import tomli_w
from ipaddress import ip_address, ip_network, summarize_address_range
from pathlib import Path

# Setup basic logging
logger = logging.getLogger("oxide_rack_validator")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

def validate_toml_file(filepath: Path) -> bool:
    """
    Ensure that the given file exists, has a .toml extension, and is parseable as TOML.
    """
    if not filepath.exists():
        logger.error(f"File does not exist: {filepath}")
        return False

    if not filepath.suffix == ".toml":
        logger.warning("File does not have a .toml extension")

    try:
        with filepath.open("rb") as f:
            data = tomllib.load(f)
        logger.info("TOML file parsed successfully.")
        return True
    except tomllib.TOMLDecodeError as e:
        logger.error(f"TOML parse error: {e}")
        return False
    except Exception as e:
        logger.exception(f"Unexpected error while parsing TOML: {e}")
        return False

def ip_pool_capacity(ip_ranges: list[dict]) -> int:
    """
    Calculates the total number of IPs in the defined internal service IP pool ranges.
    """
    count = 0
    for r in ip_ranges:
        try:
            first = ip_address(r["first"])
            last = ip_address(r["last"])
            if last >= first:
                count += int(last) - int(first) + 1
        except Exception as e:
            logger.warning(f"Invalid IP range format: {r} ({e})")
    return count

def semantic_validation(data: dict, verbose: bool = False) -> bool:
    """
    Perform semantic validation of required fields, IP pool sufficiency, and network config.
    """
    valid = True

    def info(msg):
        if verbose:
            logger.info(msg)

    # Top-level key validation
    required_keys = [
        "external_dns_zone_name",
        "external_dns_ips",
        "ntp_servers",
        "dns_servers",
        "internal_services_ip_pool_ranges",
        "bootstrap_sleds",
    ]
    info("Checking required top-level keys...")
    for key in required_keys:
        if key not in data:
            logger.error(f"Missing required key: {key}")
            valid = False

    # Internal IP pool range checks
    ip_pools = data.get("internal_services_ip_pool_ranges", [])
    count = ip_pool_capacity(ip_pools)
    info(f"Checking internal IP pools: {count} IPs found")
    if count < 12:
        logger.error(f"Fewer than required service IPs (found {count}, minimum 12 required).")
        valid = False

    # Bootstrap sleds checks
    sleds = data.get("bootstrap_sleds", [])
    info("Validating bootstrap sleds...")
    if not isinstance(sleds, list) or not all(isinstance(s, int) for s in sleds):
        logger.error("bootstrap_sleds must be a list of integers.")
        valid = False
    if not sleds:
        logger.warning("bootstrap_sleds list is empty.")

    # Validate network config per switch and BGP
    info("Validating rack_network_config nested structures...")
    network = data.get("rack_network_config", {})
    for switch_name in ("switch0", "switch1"):
        switch = network.get(switch_name, {})
        if not isinstance(switch, dict):
            logger.error(f"Expected dictionary for {switch_name} config.")
            valid = False
            continue
        for port, port_cfg in switch.items():
            if not isinstance(port_cfg, dict):
                logger.error(f"Invalid port config under {switch_name}.{port}")
                valid = False
            addresses = port_cfg.get("addresses", [])
            for addr in addresses:
                try:
                    ip_network(addr, strict=False)
                except Exception:
                    logger.error(f"Invalid IP address format on {switch_name}.{port}: {addr}")
                    valid = False

    # BGP validation
    bgp_list = network.get("bgp", [])
    info("Validating BGP configuration...")
    if not isinstance(bgp_list, list):
        logger.error("rack_network_config.bgp must be a list")
        valid = False
    else:
        for idx, bgp in enumerate(bgp_list):
            if not isinstance(bgp, dict):
                logger.error(f"Entry {idx} in rack_network_config.bgp is not a dictionary")
                valid = False
                continue
            asn = bgp.get("asn")
            if not isinstance(asn, int) or asn <= 0:
                logger.error(f"Invalid or missing ASN in BGP config entry {idx}: {asn}")
                valid = False
            prefixes = bgp.get("originate", [])
            if not isinstance(prefixes, list):
                logger.error(f"Invalid originate list in BGP config entry {idx}: {prefixes}")
                valid = False

    if valid:
        logger.info("Semantic validation passed.")
    else:
        logger.error("Semantic validation failed.")

    return valid

def summarize_config(data):
    from ipaddress import ip_address, ip_network

    print("╭──────────────────────────────────────────────╮")
    print("│     Oxide Rack Configuration Summary         │")
    print("╰──────────────────────────────────────────────╯")

    def join_or_dash(values):
        return ", ".join(values) if values else "<not set>"

    print(f"Delegated DNS zone     : {data.get('external_dns_zone_name', '<missing>')}")
    print(f"External DNS IPs       : {join_or_dash(data.get('external_dns_ips', []))}")
    print(f"Upstream DNS Servers   : {join_or_dash(data.get('dns_servers', []))}")
    print(f"NTP Servers            : {join_or_dash(data.get('ntp_servers', []))}")

    sleds = data.get("bootstrap_sleds", [])
    print(f"Bootstrap sleds        : {len(sleds)} defined")

    pools = data.get("internal_services_ip_pool_ranges", [])
    print(f"Internal IP pool ranges: {len(pools)} defined")

    total_ips = 0
    for idx, r in enumerate(pools):
        try:
            net = ip_network(f"{r['first']}/{ip_address(r['first']).max_prefixlen}", strict=False)
            end = ip_address(r["last"])
            first = ip_address(r["first"])
            count = int(end) - int(first) + 1
        except Exception:
            count = 0
        print(f"              - Range {idx+1}: {r['first']} - {r['last']} [~{count} IPs]")
        total_ips += count
    print(f"Total usable IPs       : {total_ips}\n")

    print("── Switch Port Configuration ───────────────")
    for sw_name, ports in data.get("rack_network_config", {}).items():
        if not sw_name.startswith("switch"):
            continue
        print(f"  {sw_name}:")
        for port_name, port_cfg in ports.items():

            addresses = []
            # Normalize addresses to list of strings
            if isinstance(port_cfg, dict):
                raw = port_cfg.get("addresses") or port_cfg.get("address")
                if isinstance(raw, str):
                    addresses = [raw]
                elif isinstance(raw, list):
                    addresses = [str(x) if isinstance(x, str) else x.get("address", "") for x in raw]
                elif isinstance(raw, dict):
                    addresses = [raw.get("address", "")]

            speed = port_cfg.get("uplink_port_speed", "<not set>")
            if addresses:
                print(f"    - Port {port_name}: {', '.join(addresses)}, speed: {speed}")
            else:
                print(f"    - Port {port_name}: ⚠ No valid address")

            # Flag invalid CIDRs
            invalid = []
            for a in addresses:
                try:
                    ip_network(a, strict=False)
                except Exception:
                    invalid.append(str(a))
            if invalid:
                print(f"      ⚠ Invalid CIDRs: {', '.join(str(i) for i in invalid)}")

    print("\n── BGP Configuration ───────────────────────")
    bgp = data.get("rack_network_config", {}).get("bgp", [])
    if not bgp:
        print("  Not using BGP.")
    else:
        print(f"  Using BGP with {len(bgp)} configuration(s):")
        for idx, entry in enumerate(bgp):
            print(f"    - Entry {idx+1}: ASN {entry.get('asn')}, Prefixes: {join_or_dash(entry.get('originate', []))}")



def main():
    """Command-line interface for TOML rack configuration inspection and operations."""
    parser = argparse.ArgumentParser(
        description="Oxide Rack Config Validator",
        epilog="Examples:\n  python oxide_rack_validator.py --summarize config.toml\n  python oxide_rack_validator.py --validate config.toml --verbose"
    )
    parser.add_argument("filepath", type=Path, help="Path to the TOML config file")
    parser.add_argument("--validate", action="store_true", help="Check for valid TOML syntax")
    parser.add_argument("--semantic", action="store_true", help="Validate structure and values")
    parser.add_argument("--summarize", action="store_true", help="Print a summary of the config")
    parser.add_argument("--reformat", action="store_true", help="Reformat and normalize the TOML")
    parser.add_argument("--output", type=Path, help="Optional output path when using --reformat")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    try:
        with args.filepath.open("rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        logger.error(f"Failed to load TOML file: {e}")
        sys.exit(1)

    exit_code = 0

    if args.validate:
        if not validate_toml_file(args.filepath):
            exit_code = 1

    if args.semantic:
        if not semantic_validation(data, verbose=args.verbose):
            exit_code = 1

    if args.summarize:
        summarize_config(data)

    if args.reformat:
        try:
            if args.output and str(args.output) in ("-", "tty"):
                tomli_w.dump(data, sys.stdout.buffer)
            else:
                out_path = args.output or args.filepath
                with out_path.open("wb") as f:
                    tomli_w.dump(data, f)
                logger.info(f"Reformatted TOML written to {out_path}")
        except Exception as e:
            logger.error(f"Failed to reformat TOML: {e}")
            exit_code = 1

    if not any([args.validate, args.semantic, args.summarize, args.reformat]):
        parser.print_help()
        sys.exit(1)

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
