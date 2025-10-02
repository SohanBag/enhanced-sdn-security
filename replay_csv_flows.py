#!/usr/bin/env python3
import warnings
warnings.filterwarnings("ignore", message="getmacbyip failed.*")

import argparse
import pandas as pd
from scapy.all import Ether, IP, TCP, UDP
from scapy.utils import PcapWriter

def safe(val, default):
    if pd.isnull(val) or val == "":
        return default
    return val

def main():
    parser = argparse.ArgumentParser(
        description="Generate a PCAP of synthetic flows from CSV"
    )
    parser.add_argument("--csv", required=True,
                        help="Path to filtered_combined_dataset.csv")
    parser.add_argument("--outfile", default="synthetic_flows.pcap",
                        help="Output PCAP filename")
    args = parser.parse_args()

    df = pd.read_csv(args.csv, dtype=str, low_memory=False)
    writer = PcapWriter(args.outfile, append=False, sync=True)
    total = 0

    # Use fixed dummy MACs so Scapy won’t ARP at all
    DUMMY_SRC_MAC = "00:11:22:33:44:55"
    DUMMY_DST_MAC = "66:77:88:99:AA:BB"

    for _, row in df.iterrows():
        src_ip   = safe(row.get("Source IP"),       "10.0.0.1")
        dst_ip   = safe(row.get("Destination IP"),  "10.0.0.2")
        sport    = int(safe(row.get("Source Port"),     "12345"))
        dport    = int(safe(row.get("Destination Port"), "80"))
        proto    = int(safe(row.get("Protocol"),        "6"))
        fwd_pkts = int(safe(row.get("Total Fwd Packets"),      "0"))
        bwd_pkts = int(safe(row.get("Total Backward Packets"), "0"))

        if (fwd_pkts + bwd_pkts) == 0:
            continue

        # Build packet templates with dummy MACs
        if proto == 6:  # TCP
            fwd_tmpl = Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC)/IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA")
            bwd_tmpl = Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC)/IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="PA")
        elif proto == 17:  # UDP
            fwd_tmpl = Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC)/IP(src=src_ip, dst=dst_ip)/UDP(sport=sport, dport=dport)
            bwd_tmpl = Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC)/IP(src=dst_ip, dst=src_ip)/UDP(sport=dport, dport=sport)
        else:
            fwd_tmpl = Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC)/IP(src=src_ip, dst=dst_ip)
            bwd_tmpl = Ether(src=DUMMY_SRC_MAC, dst=DUMMY_DST_MAC)/IP(src=dst_ip, dst=src_ip)

        # Write to PCAP
        for _ in range(fwd_pkts):
            writer.write(fwd_tmpl); total += 1
        for _ in range(bwd_pkts):
            writer.write(bwd_tmpl); total += 1

    writer.close()
    print(f"Written {total} packets to {args.outfile}")

if __name__ == "__main__":
    main()

