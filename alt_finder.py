#!/usr/bin/env python3
import argparse
import datetime
import gzip
import os
import re
import glob
from collections import defaultdict, deque

def parse_logs(directory, file_pattern, since=None):
    """
    Scan all files matching the file_pattern in the given directory (recursively)
    and extract login events. If 'since' is provided (a datetime object), only files
    with a modification time on or after 'since' are processed.
    """
    player_to_ips = defaultdict(set)
    ip_to_players = defaultdict(set)

    # Regex to match login events.
    # Example line:
    # 27340:[22:40:23] [Region Scheduler Thread #3/INFO]: kouchklinktrane[/5.144.73.108:54424] logged in with entity id 3189557 ...
    login_regex = re.compile(
        r':\s*(\S+)\[(?:/)?(\d+\.\d+\.\d+\.\d+):\d+\]\s+logged in with entity id'
    )

    # Build a glob pattern that will match both gzipped and non-gzipped files.
    pattern = os.path.join(directory, '**', file_pattern)
    files = glob.glob(pattern, recursive=True)
    print(f"Found {len(files)} file(s) matching pattern: {pattern}")

    file_count = 0
    match_count = 0
    for filename in files:
        # If --since was provided, check file modification time.
        if since is not None:
            try:
                file_mtime = os.path.getmtime(filename)
                if file_mtime < since.timestamp():
                    # Skip files older than the specified date.
                    continue
            except Exception as e:
                print(f"Could not get modification time for {filename}: {e}")
                continue

        file_count += 1
        try:
            # Open gzipped files with gzip.open, otherwise use normal open.
            if filename.endswith('.gz'):
                file_handle = gzip.open(filename, 'rt', errors='ignore')
            else:
                file_handle = open(filename, 'r', encoding='utf-8', errors='ignore')
            with file_handle as f:
                for line in f:
                    m = login_regex.search(line)
                    if m:
                        match_count += 1
                        player, ip = m.groups()
                        player_to_ips[player].add(ip)
                        ip_to_players[ip].add(player)
        except Exception as e:
            print(f"Error processing {filename}: {e}")

    print(f"Processed {file_count} file(s), found {match_count} login entry(ies).")
    return player_to_ips, ip_to_players

def get_alt_chain_paths(start, player_to_ips, ip_to_players):
    """
    Perform a breadth-first search starting from 'start' to find all players
    connected by shared IPs. Returns a tuple (parent, visited, discovered_order) where:
      - parent: a dict mapping each encountered player (except start) to a tuple (prev, ip)
                indicating that 'prev' connects to that player via 'ip'.
      - visited: the set of all players in the connected component.
      - discovered_order: a list of players (other than start) in the order they were discovered.
    """
    queue = deque([start])
    visited = {start}
    parent = {}  # key: player, value: (previous player, connecting IP)
    discovered_order = []
    while queue:
        current = queue.popleft()
        for ip in player_to_ips.get(current, []):
            # Iterate over the players sharing the IP.
            for neighbor in ip_to_players.get(ip, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    parent[neighbor] = (current, ip)
                    queue.append(neighbor)
                    discovered_order.append(neighbor)
    return parent, visited, discovered_order

def reconstruct_chain_path(alt, parent, hide_ip=False):
    """
    Reconstructs the chain path from the starting player to 'alt' using the 'parent' map.
    If hide_ip is False, returns a string showing the chain in the form:
      start -> intermediate (via connecting_ip) -> alt (via connecting_ip)
    If hide_ip is True, returns a string showing only the chain of players:
      start -> intermediate -> alt
    """
    # If there is no parent, then alt is the starting node.
    if alt not in parent:
        return alt
    path = []
    current = alt
    while current in parent:
        prev, ip = parent[current]
        path.append((prev, ip, current))
        current = prev
    path.reverse()
    chain_str = path[0][0]  # starting player name
    for prev, ip, curr in path:
        if hide_ip:
            chain_str += f" -> {curr}"
        else:
            chain_str += f" -> {curr} (via {ip})"
    return chain_str

def main():
    parser = argparse.ArgumentParser(
        description="Find alternate accounts (alts) based on IP addresses in your logs."
    )
    parser.add_argument(
        "query",
        help="Either an IPv4 address (e.g. 5.144.73.108) or a player name."
    )
    parser.add_argument(
        "--dir", default=".",
        help="Directory to search for log files (default: current directory)"
    )
    parser.add_argument(
        "--pattern", default="*.log*",
        help="Glob pattern for log files (default: *.log*). This pattern matches both plain text logs (e.g. latest.log) and gzipped logs (e.g. *.log.gz)"
    )
    parser.add_argument(
        "--chain", action="store_true",
        help="Recursively build and display alternate account chains (alt chains) connecting accounts."
    )
    parser.add_argument(
        "--since",
        help="Only process log files modified since this ISO date (e.g. 2025-02-14T00:00:00)"
    )
    parser.add_argument(
        "--hide-ip", action="store_true",
        help="Hide IP addresses in the alt chain output."
    )
    parser.add_argument(
        "--flat-chain", action="store_true",
        help="Display a single flat chain of all connected accounts (separated by ' - ') instead of separate chain paths."
    )
    args = parser.parse_args()

    # If --since is provided, parse the ISO date.
    since_dt = None
    if args.since:
        try:
            since_dt = datetime.datetime.fromisoformat(args.since)
        except Exception as e:
            print(f"Error parsing --since date: {e}")
            return

    player_to_ips, ip_to_players = parse_logs(args.dir, args.pattern, since=since_dt)
    query = args.query.strip()

    # Determine if query is an IP address.
    ip_pattern = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
    if ip_pattern.match(query):
        players = ip_to_players.get(query, set())
        if not players:
            print(f"No players found with IP {query}")
        else:
            print(f"Players using IP {query}:")
            for player in sorted(players):
                ips = sorted(player_to_ips.get(player, []))
                print(f"  {player}: {', '.join(ips)}")
    else:
        ips = player_to_ips.get(query, set())
        if not ips:
            print(f"No login entries found for player '{query}'")
        else:
            print(f"Player '{query}' has logged in from IP(s): {', '.join(sorted(ips))}")
            alt_players = set()
            for ip in ips:
                alt_players.update(ip_to_players.get(ip, set()))
            alt_players.discard(query)
            if alt_players:
                print("\nOther players using these IP(s):")
                for alt in sorted(alt_players):
                    alt_ips = sorted(player_to_ips.get(alt, []))
                    print(f"  {alt}: {', '.join(alt_ips)}")
            else:
                print("\nNo alternate accounts found sharing the same IP(s).")

            # If the chain flag is enabled, build and display the alt chains.
            if args.chain:
                parent, chain_nodes, discovered_order = get_alt_chain_paths(query, player_to_ips, ip_to_players)
                if len(chain_nodes) == 1:
                    print("\nNo alternate account chain found.")
                else:
                    if args.flat_chain:
                        # Build a single flat chain: use the order in which nodes were discovered,
                        # then append the queried account at the end.
                        if discovered_order:
                            flat_chain = " - ".join(discovered_order + [query])
                            print("\nAlternate account flat chain:")
                            print(f"  {flat_chain}")
                        else:
                            print("\nNo alternate account chain found.")
                    else:
                        print("\nAlternate account chains:")
                        # For each account in the connected component (except the query),
                        # reconstruct and display the chain path.
                        for alt in sorted(chain_nodes):
                            if alt == query:
                                continue
                            chain_str = reconstruct_chain_path(alt, parent, hide_ip=args.hide_ip)
                            print(f"  {chain_str}")

if __name__ == '__main__':
    main()
