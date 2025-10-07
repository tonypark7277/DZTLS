#!/usr/bin/env python3
import argparse
import os
import re
from datetime import datetime
from glob import glob
import pandas as pd

# 로그 라인 예:
# INFO:root:[T0 initial-send-queued] 2025-10-06T06:30:35.509 (starting QUIC handshake)
# INFO:root:[T1 handshake-completed] 2025-10-06T06:30:35.591
# INFO:root:[T2 appdata-sent] 2025-10-06T06:30:35.591 (26 bytes)
# INFO:root:[T3 appdata-received] 2025-10-06T06:30:35.660 (0 bytes) -> b''

TS_RE = re.compile(r"\[(T[0-3])\s+[^\]]*\]\s+([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+)")

def parse_iso(s: str):
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None

def main():
    ap = argparse.ArgumentParser(description="Parse QUIC client logs to Excel")
    ap.add_argument("--dir", default="results", help="directory containing .txt logs (default: ohio_results)")
    ap.add_argument("--out", default="results/summary.xlsx", help="output Excel path (default: results/summary.xlsx)")
    ap.add_argument("--recursive", action="store_true", help="search recursively for .txt files")
    args = ap.parse_args()

    search_pattern = os.path.join(args.dir, "**", "*.txt") if args.recursive else os.path.join(args.dir, "*.txt")
    files = sorted(glob(search_pattern, recursive=args.recursive))

    if not files:
        raise SystemExit(f"No .txt files found in '{args.dir}'. (hint: check path or use --recursive)")

    rows = []
    for path in files:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # T0~T3 찾기
        matches = TS_RE.findall(content)
        tmap = {}
        for tag, ts in matches:
            tmap[tag] = ts  # 같은 태그가 여러 번이면 마지막 것을 사용

        # 매핑: 로그 T0..T3 -> 리포트 T1..T4
        T1 = tmap.get("T0")  # initial-send-queued
        T2 = tmap.get("T1")  # handshake-completed
        T3 = tmap.get("T2")  # appdata-sent
        T4 = tmap.get("T3")  # appdata-received

        pT1 = parse_iso(T1) if T1 else None
        pT2 = parse_iso(T2) if T2 else None
        pT3 = parse_iso(T3) if T3 else None
        pT4 = parse_iso(T4) if T4 else None

        def ms(a, b):
            if a is None or b is None:
                return None
            return (b - a).total_seconds() * 1000.0

        handshake_ms = ms(pT1, pT2)  # T2 - T1
        appdata_rtt_ms = ms(pT3, pT4)  # T4 - T3
        end_to_end_ms = ms(pT1, pT4)  # T4 - T1

        base = os.path.basename(path)
        label = ""
        m = re.match(r"run_([^_]+)_\d+_", base)
        if m:
            label = m.group(1)

        rows.append({
            "file": base,
            "label": label,
            "T1": T1,
            "T2": T2,
            "T3": T3,
            "T4": T4,
            "handshake_ms (T2-T1)": handshake_ms,
            "appdata_rtt_ms (T4-T3)": appdata_rtt_ms,
            "end_to_end_ms (T4-T1)": end_to_end_ms,
        })

    df = pd.DataFrame(rows, columns=[
        "file", "label", "T1", "T2", "T3", "T4",
        "handshake_ms (T2-T1)", "appdata_rtt_ms (T4-T3)", "end_to_end_ms (T4-T1)"
    ])

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    # 엑셀 저장
    with pd.ExcelWriter(args.out, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="summary")

    # 요약 출력
    print(f"[OK] Parsed {len(df)} files → {args.out}")

if __name__ == "__main__":
    main()

