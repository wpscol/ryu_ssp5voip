#!/usr/bin/env python3
"""
Real-time OpenFlow flow table monitor for SSP5 VoIP SDN network.
Displays flow types and statistics for all switches in a formatted table.
"""

import subprocess
import time
import re
from collections import defaultdict
from datetime import datetime

try:
    from tabulate import tabulate
except ImportError:
    print("Error: tabulate library not found. Installing...")
    subprocess.run(["pip", "install", "tabulate"], check=True)
    from tabulate import tabulate


def run_ovs_cmd(switch, command="dump-flows"):
    """Execute ovs-ofctl command and return output."""
    try:
        cmd = ["sudo", "ovs-ofctl", "-O", "OpenFlow13", command, switch]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        return f"Error: {e}"


def parse_flows(flow_output):
    """Parse ovs-ofctl output and categorize flows by type."""
    flow_stats = {
        'total': 0,
        'voip_udp': 0,      # Priority 100 UDP flows (VoIP)
        'tcp': 0,           # Priority 1 TCP flows
        'other': 0,
        'priorities': defaultdict(int),
        'protocols': defaultdict(int)
    }

    if not flow_output or "Error" in flow_output:
        return flow_stats

    lines = flow_output.strip().split('\n')

    for line in lines:
        # Skip header and empty lines
        if not line or line.startswith('NXST') or line.startswith('OFPST'):
            continue

        flow_stats['total'] += 1

        # Extract priority
        priority_match = re.search(r'priority=(\d+)', line)
        priority = int(priority_match.group(1)) if priority_match else 0
        flow_stats['priorities'][priority] += 1

        # Check protocol
        if 'udp' in line.lower() or 'ip_proto=17' in line:
            flow_stats['protocols']['UDP'] += 1
            if priority == 100:
                flow_stats['voip_udp'] += 1
        elif 'tcp' in line.lower() or 'ip_proto=6' in line:
            flow_stats['protocols']['TCP'] += 1
            if priority == 1:
                flow_stats['tcp'] += 1
        elif 'arp' in line.lower():
            flow_stats['protocols']['ARP'] += 1
        else:
            flow_stats['other'] += 1

    return flow_stats


def display_table(switch_data):
    """Display flow information in a formatted table using tabulate."""
    # Clear screen (works on Unix-like systems)
    print("\033[2J\033[H", end="")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n SSP5 VoIP SDN - OpenFlow Table Monitor")
    print(f" {timestamp}\n")

    # Prepare table data
    table_data = []
    for switch in sorted(switch_data.keys()):
        stats = switch_data[switch]

        # Total flows
        total = stats['total']

        # VoIP count
        voip = stats['voip_udp']

        # TCP count
        tcp = stats['tcp']

        # Other count
        other = stats['other']

        # Priorities breakdown
        if stats['priorities']:
            priorities = ", ".join([f"P{p}:{c}" for p, c in sorted(stats['priorities'].items(), reverse=True)])
        else:
            priorities = "-"

        # Protocols breakdown
        if stats['protocols']:
            protocols = ", ".join([f"{proto}:{count}" for proto, count in sorted(stats['protocols'].items())])
        else:
            protocols = "-"

        table_data.append([switch, total, voip, tcp, other, priorities, protocols])

    # Define headers
    headers = ["Switch", "Total", "VoIP", "TCP", "Other", "Priorities", "Protocols"]

    # Display table with grid format
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

    # Legend
    print("\nLegend:")
    print("  VoIP:  High-priority UDP flows (priority=100) for VoIP traffic")
    print("  TCP:   Normal TCP flows (priority=1) distributed via round-robin")
    print("  Other: Non-TCP/VoIP flows (ARP, etc.)")
    print("  P100:  Priority 100 (VoIP), P1: Priority 1 (Normal traffic)")
    print("\nPress Ctrl+C to exit")


def monitor_switches(switches, interval=1):
    """Continuously monitor switches and display flow tables."""
    try:
        while True:
            switch_data = {}

            for switch in switches:
                flow_output = run_ovs_cmd(switch)
                stats = parse_flows(flow_output)
                switch_data[switch] = stats

            display_table(switch_data)
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n✓ Monitoring stopped")


def main():
    """Main entry point."""
    # SSP5 VoIP topology has 6 switches
    switches = ['s1', 's2', 's3', 's4', 's5', 's6']

    print("Starting flow monitor for SSP5 VoIP SDN network...")
    print("Checking switch connectivity...\n")

    # Verify switches are reachable
    available_switches = []
    for switch in switches:
        result = run_ovs_cmd(switch)
        if result and "Error" not in result:
            available_switches.append(switch)
            print(f"  ✓ {switch} is online")
        else:
            print(f"  ✗ {switch} is not reachable")

    if not available_switches:
        print("\n✗ No switches found. Make sure Mininet is running:")
        print("  sudo /usr/bin/python3 mininet/topology.py")
        return 1

    print(f"\n✓ Found {len(available_switches)} switches")
    print("\nStarting real-time monitoring...\n")
    time.sleep(2)

    monitor_switches(available_switches, interval=1)
    return 0


if __name__ == "__main__":
    exit(main())
