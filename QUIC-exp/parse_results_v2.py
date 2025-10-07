#!/usr/bin/env python3
"""
Parse QUIC client logs (TXT) and export to Excel.

Adds support for:
  - T0 (initial queued)
  - T_retry (Retry token received)
  - retry_gap_ms (T_retry - T0)
  - post_retry_to_hs_ms (T1 - T_retry)

Still extracts:
  - T1, T2, T3, T4 (T4 from SUMMARY recv=..., else T3)
  - handshake_ms (T2 - T1)
  - recv_gap_ms (T4 - T3)
  - span_ms (T4 - T1)

Usage:
  python parse_results_v2.py --input result --output quic_results_v2.xlsx
"""

import argparse
import glob
import os
import re
from datetime import datetime
from typing import Optional, Dict, Any, List

import pandas as pd

# Regexes
T0_RE = re.compile(r'\[T0\s+initial-send-queued\]\s+(\S+)')
TRETRY_RE = re.compile(r'\[T_retry\s+retry-token-received\]\s+(\S+)')
T1_RE = re.compile(r'\[T1\s+handshake-completed\]\s+(\S+)')
T2_RE = re.compile(r'\[T2\s+appdata-sent\]\s+(\S+)\s+\((\d+)\s+bytes\)')
T3_RE = re.compile(r'\[T3\s+appdata-received\]\s+(\S+)\s+\((\d+)\s+bytes\)')
SUMMARY_RECV_RE = re.compile(r'recv=(\S+)')

def parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None

def duration_ms(a: Optional[datetime], b: Optional[datetime]) -> Optional[float]:
    if a is None or b is None:
        return None
    return (b - a).total_seconds() * 1000.0

def parse_file(path: str) -> Dict[str, Any]:
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    # Extract timestamps as strings
    t0_s = (T0_RE.search(text) or [None, None])[1]
    tr_s = (TRETRY_RE.search(text) or [None, None])[1]
    t1_s = (T1_RE.search(text) or [None, None])[1]
    t2_match = T2_RE.search(text)
    t3_match = T3_RE.search(text)

    t2_s = t2_match.group(1) if t2_match else None
    t2_bytes = int(t2_match.group(2)) if t2_match else None

    t3_s = t3_match.group(1) if t3_match else None
    t3_bytes = int(t3_match.group(2)) if t3_match else None

    m = SUMMARY_RECV_RE.search(text)
    t4_s = m.group(1) if m else t3_s  # fallback to T3 if no SUMMARY recv=

    # Parse to datetime for duration math
    t0 = parse_iso(t0_s)
    tr = parse_iso(tr_s)
    t1 = parse_iso(t1_s)
    t2 = parse_iso(t2_s)
    t3 = parse_iso(t3_s)
    t4 = parse_iso(t4_s)

    row = {
        'file': os.path.basename(path),
        'path': os.path.abspath(path),
        # Raw timestamps
        'T0': t0_s,
        'T_retry': tr_s,
        'T1': t1_s,
        'T2': t2_s,
        'T3': t3_s,
        'T4': t4_s,
        # Durations (ms)
        'retry_gap_ms (T_retry-T0)': duration_ms(t0, tr),
        'post_retry_to_hs_ms (T1-T_retry)': duration_ms(tr, t1),
        'handshake_ms (T2-T1)': duration_ms(t1, t2),
        'recv_gap_ms (T4-T3)': duration_ms(t3, t4),
        'span_ms (T4-T1)': duration_ms(t1, t4),
        # Extras
        'sent_bytes (from T2)': t2_bytes,
        'recv_bytes (from T3)': t3_bytes,
    }
    return row

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="results", help="directory containing .txt logs (default: results)")
    ap.add_argument("--out", default="results/summary.xlsx", help="output Excel path (default: results/summary.xlsx)")
    ap.add_argument("--recursive", action="store_true", help="search recursively for .txt files")
    args = ap.parse_args()

    pattern = os.path.join(args.dir, "**", "*.txt") if args.recursive else os.path.join(args.dir, "*.txt")
    files = sorted(glob.glob(pattern, recursive=True))
    if not files:
        print(f'No .txt files found under: {args.input}')
        return

    rows: List[Dict[str, Any]] = []
    for p in files:
        try:
            rows.append(parse_file(p))
        except Exception as e:
            rows.append({
                'file': os.path.basename(p),
                'path': os.path.abspath(p),
                'T0': None, 'T_retry': None, 'T1': None, 'T2': None, 'T3': None, 'T4': None,
                'retry_gap_ms (T_retry-T0)': None,
                'post_retry_to_hs_ms (T1-T_retry)': None,
                'handshake_ms (T2-T1)': None,
                'recv_gap_ms (T4-T3)': None,
                'span_ms (T4-T1)': None,
                'sent_bytes (from T2)': None,
                'recv_bytes (from T3)': None,
                'error': str(e),
            })

    df = pd.DataFrame(rows)

    try:
        df = df.sort_values(by=['file'])
    except Exception:
        pass

    out_path = os.path.abspath(args.out)
    with pd.ExcelWriter(out_path, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='results')

    print(f'Wrote Excel: {out_path}')
    with pd.option_context('display.max_rows', 5, 'display.width', 160):
        print(df.head())

if __name__ == '__main__':
    main()
