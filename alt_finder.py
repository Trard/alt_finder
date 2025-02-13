#!/usr/bin/env python3
import argparse
import gzip
import os
import re
import glob
from collections import defaultdict

def parse_logs(directory, file_pattern):
    """
    Scan all files matching the file_pattern in the given directory (recursively)
    and extract login events.
    """
    player_to_ips = defaultdict(set)
    ip_to_players = defaultdict(set)
    
    # Regex to match login events.
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
    args = parser.parse_args()

    player_to_ips, ip_to_players = parse_logs(args.dir, args.pattern)
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

if __name__ == '__main__':
    main()
