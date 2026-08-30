import csv
import fnmatch
import os
import re
import time
from datetime import datetime

import utils.helpers as helpers
import utils.paths as paths
import cores.ui_layout as ui_layout
import utils.asn_engine as asn_engine


ASN_FAMILY_FILES = {
    "ipv4": ("filtered_ipv4.csv",),
    "ipv6": ("filtered_ipv6.csv",),
    "both": ("filtered_ipv4.csv", "filtered_ipv6.csv"),
}


def _choose_ip_family():
    print(ui_layout.color_text(" ASN IP FAMILY", "mode_white"))
    print(" [1] IPv4 (filtered_ipv4.csv)")
    print(" [2] IPv6 (filtered_ipv6.csv)")
    print(" [3] Both IPv4 + IPv6")
    while True:
        choice = input("\nSelect IP family [1]: ").strip().lower()
        if choice in ("", "1", "ipv4", "v4"):
            return "ipv4"
        if choice in ("2", "ipv6", "v6"):
            return "ipv6"
        if choice in ("3", "both", "all"):
            return "both"
        ui_layout.print_err("Choose 1 (IPv4), 2 (IPv6), or 3 (Both).")


def _load_asn_db(family="both"):
    family = family if family in ASN_FAMILY_FILES else "both"
    asn_db = {}
    seen = {}
    loaded_files = 0
    for filename in ASN_FAMILY_FILES[family]:
        csv_path = paths.root_path("IranASNs", filename)
        if not os.path.exists(csv_path):
            ui_layout.print_err(f"ASN database not found at IranASNs/{filename}")
            continue
        loaded_files += 1
        with open(csv_path, 'r', encoding='utf-8', newline='') as file:
            reader = csv.reader(file)
            next(reader, None)
            for row in reader:
                if len(row) < 9:
                    continue
                subnet, asn, name = row[0].strip(), row[5].strip(), row[6].strip()
                if not subnet or not asn:
                    continue
                key = f"{asn} - {name}"
                if key not in asn_db:
                    asn_db[key] = []
                    seen[key] = set()
                if subnet not in seen[key]:
                    seen[key].add(subnet)
                    asn_db[key].append(subnet)

    if loaded_files == 0:
        return {}

    return asn_db


def _filter_asns(asn_db, query):
    """
    Filter ASNs by query. Supports:
    - '*' or 'all': match all ASNs
    - 'regex:pattern': explicit regex matching
    - '^pattern' or 'pattern$': regex anchors (treated as regex)
    - '*pattern*': fnmatch wildcard
    - 'pattern': substring match (case-insensitive)
    """
    if query in ['*', 'all']:
        results = list(asn_db.keys())
    elif query.startswith('regex:'):
        # Explicit regex mode
        pattern_str = query[6:].strip()
        try:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            results = [key for key in asn_db.keys() if pattern.search(key)]
        except re.error as e:
            ui_layout.print_err(f"Invalid regex: {e}")
            results = []
    elif query.startswith('^') or query.endswith('$') or query.startswith('(') or '|' in query:
        # Likely a regex pattern
        try:
            pattern = re.compile(query, re.IGNORECASE)
            results = [key for key in asn_db.keys() if pattern.search(key)]
        except re.error:
            # Fall back to wildcard if not valid regex
            results = [key for key in asn_db.keys() if fnmatch.fnmatch(key.lower(), query)]
    elif '*' in query:
        results = [key for key in asn_db.keys() if fnmatch.fnmatch(key.lower(), query)]
    else:
        results = [key for key in asn_db.keys() if query in key.lower()]

    results.sort(key=lambda key: len(asn_db[key]), reverse=True)
    return results


def _toggle_selection_tokens(tokens, results, selected_keys):
    for token in tokens:
        if '-' in token:
            try:
                start_raw, end_raw = token.split('-', 1)
                start_idx = int(start_raw)
                end_idx = int(end_raw)
                if start_idx > end_idx:
                    start_idx, end_idx = end_idx, start_idx
                for index in range(start_idx, end_idx + 1):
                    if 1 <= index <= len(results):
                        key = results[index - 1]
                        if key in selected_keys:
                            selected_keys.remove(key)
                        else:
                            selected_keys.add(key)
            except Exception:
                continue
        elif token.isdigit():
            index = int(token)
            if 1 <= index <= len(results):
                key = results[index - 1]
                if key in selected_keys:
                    selected_keys.remove(key)
                else:
                    selected_keys.add(key)


def menu_search_asn(show_queue_message=True, family=None):
    family = family or _choose_ip_family()
    asn_db = _load_asn_db(family)
    if not asn_db:
        time.sleep(1.5)
        return []

    query = "*"
    page = 0
    per_page = 15
    selected_keys = set()

    while True:
        results = _filter_asns(asn_db, query)
        total_pages = max(1, (len(results) + per_page - 1) // per_page)
        page = max(0, min(page, total_pages - 1))

        start_idx = page * per_page
        end_idx = start_idx + per_page
        page_items = results[start_idx:end_idx]

        helpers.clear_screen()
        line = ui_layout.color_text("═" * 70, "dim")
        print(line)
        print(ui_layout.color_text(" INTERACTIVE ASN BROWSER", "mode_white"))
        print(line)
        print(f" IP Family    : {family.upper()}")
        print(f" Search Query : {query}")
        print(f" Total Matches: {len(results)} ASNs")
        print(f" Selected ASNs: {len(selected_keys)}")
        print(line + "\n")

        if not page_items:
            ui_layout.print_err("No matching ASNs found for this query.")
        else:
            for offset, key in enumerate(page_items):
                absolute_idx = start_idx + offset + 1
                marker = "[X]" if key in selected_keys else "[ ]"
                clean_key = key[:58] + "..." if len(key) > 61 else key
                print(f" {absolute_idx:>4}. {marker} {clean_key:<62} ({len(asn_db[key])} subnets)")

        print(f"\n--- Page {page + 1}/{total_pages} ---")
        print(ui_layout.color_text(" Commands", "nav"))
        print(" [1,2,5-8] Toggle ASN selection")
        print(" [/text]    Search (substring match)")
        print(" [/*pat*]   Wildcard search")
        print(" [/regex:]  Regex search (example: /regex:^AS\\d+(mobile|.*mci))")
        print(" [/^pat$]   Regex anchors (example: /^AS58224)")
        print(" [n]/[p]    Next/Previous page")
        print(" [all]      Select all current matches")
        print(" [clear]    Clear all selections")
        print(" [d]        Done and queue subnets")
        print(" [0]        Cancel")

        cmd = input("\nAction: ").strip().lower()
        if not cmd:
            continue
        if cmd in ['0', 'q']:
            return []
        if cmd == 'n':
            page += 1
            continue
        if cmd == 'p':
            page -= 1
            continue
        if cmd == 'all':
            selected_keys.update(results)
            continue
        if cmd == 'clear':
            selected_keys.clear()
            continue
        if cmd == 'd':
            if not selected_keys:
                ui_layout.print_err("Select at least one ASN before continuing.")
                time.sleep(1)
                continue
            break
        if cmd.startswith('/'):
            query = cmd[1:].strip().lower() or "*"
            page = 0
            continue

        tokens = cmd.replace(',', ' ').split()
        _toggle_selection_tokens(tokens, results, selected_keys)

    selected_subnets = []
    for key in selected_keys:
        selected_subnets.extend(asn_db[key])

    if show_queue_message:
        ui_layout.print_ok(f"Queued {len(selected_subnets)} subnets from {len(selected_keys)} ASNs.")
        time.sleep(1.2)
    return selected_subnets


def _default_asn_export_path():
    export_dir = paths.runtime_path("exports")
    paths.ensure_dir(export_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(export_dir, f"asn_ips_{timestamp}.txt")


def menu_export_asn_ips():
    subnets = menu_search_asn(show_queue_message=False)
    if not subnets:
        return

    default_path = _default_asn_export_path()
    output_path = input(f"Output txt path [Default: {default_path}]: ").strip()
    if not output_path:
        output_path = default_path

    output_path = os.path.abspath(os.path.expanduser(output_path))
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    exported_ips = []
    seen_ips = set()
    for subnet in subnets:
        for ip in asn_engine.expand_target(subnet, silent=True):
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            exported_ips.append(ip)

    if not exported_ips:
        ui_layout.print_err("No IPs were expanded from the selected ASNs.")
        time.sleep(1.2)
        return

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("# ASN IP export\n")
        handle.write(f"# Generated: {datetime.now().isoformat(timespec='seconds')}\n")
        handle.write(f"# Source subnets: {len(subnets)}\n")
        handle.write(f"# Expanded IPs: {len(exported_ips)}\n\n")
        handle.write("\n".join(exported_ips))
        handle.write("\n")

    ui_layout.print_ok(f"Exported {len(exported_ips)} IPs to {output_path}")
    time.sleep(1.5)


def menu_browse_asn_db():
    family = _choose_ip_family()
    asn_db = _load_asn_db(family)
    if not asn_db:
        time.sleep(1.5)
        return

    query = "*"
    page = 0
    per_page = 15

    while True:
        results = _filter_asns(asn_db, query)
        total_pages = max(1, (len(results) + per_page - 1) // per_page)
        page = max(0, min(page, total_pages - 1))

        start_idx = page * per_page
        end_idx = start_idx + per_page
        page_items = results[start_idx:end_idx]

        helpers.clear_screen()
        line = ui_layout.color_text("═" * 70, "dim")
        print(line)
        print(ui_layout.color_text(" ASN DATABASE BROWSER", "mode_white"))
        print(line)
        print(f" IP Family    : {family.upper()}")
        print(f" Search Query : {query}")
        print(f" Total Matches: {len(results)} ASNs")
        print(line + "\n")

        if not page_items:
            ui_layout.print_err("No matching ASNs found for this query.")
        else:
            for offset, key in enumerate(page_items):
                absolute_idx = start_idx + offset + 1
                clean_key = key[:58] + "..." if len(key) > 61 else key
                print(f" [{absolute_idx:>3}] {clean_key:<62} ({len(asn_db[key])} subnets)")

        print(f"\n--- Page {page + 1}/{total_pages} ---")
        print(ui_layout.color_text(" Commands", "nav"))
        print(" [1,2...]    View ASN subnets")
        print(" [/text]     Search")
        print(" [n]/[p]     Next/Previous page")
        print(" [0]         Back")

        cmd = input("\nAction: ").strip().lower()
        if not cmd:
            continue
        if cmd in ['0', 'q']:
            return
        if cmd == 'n':
            page += 1
            continue
        if cmd == 'p':
            page -= 1
            continue
        if cmd.startswith('/'):
            query = cmd[1:].strip().lower() or "*"
            page = 0
            continue
        if not cmd.isdigit():
            continue

        selected_index = int(cmd)
        if not (1 <= selected_index <= len(results)):
            continue

        selected_key = results[selected_index - 1]
        subnets = asn_db[selected_key]

        sub_page = 0
        sub_per_page = 60
        sub_total_pages = max(1, (len(subnets) + sub_per_page - 1) // sub_per_page)

        while True:
            helpers.clear_screen()
            line = ui_layout.color_text("═" * 70, "dim")
            print(line)
            print(ui_layout.color_text(f" SUBNETS: {selected_key}", "mode_white"))
            print(line)
            print(f" Total Subnets: {len(subnets)}")
            print(line + "\n")

            start_sub = sub_page * sub_per_page
            end_sub = start_sub + sub_per_page
            view_subnets = subnets[start_sub:end_sub]

            for row in range(0, len(view_subnets), 3):
                col1 = view_subnets[row] if row < len(view_subnets) else ""
                col2 = view_subnets[row + 1] if row + 1 < len(view_subnets) else ""
                col3 = view_subnets[row + 2] if row + 2 < len(view_subnets) else ""
                print(f" {col1:<20} {col2:<20} {col3:<20}")

            print(f"\n--- Page {sub_page + 1}/{sub_total_pages} ---")
            print(" Commands: [n] Next  [p] Previous  [0] Back")

            sub_cmd = input("\nAction: ").strip().lower()
            if sub_cmd == 'n' and sub_page < sub_total_pages - 1:
                sub_page += 1
            elif sub_cmd == 'p' and sub_page > 0:
                sub_page -= 1
            elif sub_cmd in ['0', 'q']:
                break
