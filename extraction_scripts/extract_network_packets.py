import subprocess
import os
import csv
import hashlib
import concurrent.futures
import time

# --- CONFIGURATION ---
PCAP_FOLDER = r"./input_pcaps/"
OUTPUT_CSV = "S6_Network_Packets_Anonymized.csv"
MAX_WORKERS = os.cpu_count()

# --- PROTOCOL MAP & PORTS ---
# TShark Filter Syntax
TSHARK_FILTER = "tcp.port in {2404, 1883, 8883} or udp.port in {161, 162}"

OT_PORTS = {
    '2404': 'IEC 60870-5-104',
    '1883': 'MQTT',
    '8883': 'MQTT-TLS',
    '161':  'SNMP',
    '162':  'SNMP-Trap'
}

# --- ANONYMIZATION ---
SALT = "INSERT_YOUR_PRIVATE_SALT_HERE"

def anonymize_ip(ip_addr):
    if not ip_addr or ip_addr == "": return "Unknown"
    raw = f"{ip_addr}{SALT}".encode()
    return f"Node_{hashlib.sha256(raw).hexdigest()[:6]}"

def process_single_file(file_path):
    """
    Runs a TShark subprocess on a single file and returns the processed rows.
    """
    rows = []
    
    # TShark Command: Extract only specific fields as CSV text
    # -n: No name resolution (Critical for speed!)
    # -r: Read file
    # -Y: Display Filter (The "RTU Filter")
    # -T fields: Output fields only
    # -E separator=,: Use comma separator
    cmd = [
        'tshark', '-n', '-r', file_path,
        '-Y', TSHARK_FILTER,
        '-T', 'fields',
        '-E', 'separator=,',
        '-e', 'frame.time_epoch', # 0
        '-e', 'ip.src',           # 1
        '-e', 'ip.dst',           # 2
        '-e', 'tcp.srcport',      # 3
        '-e', 'udp.srcport',      # 4
        '-e', 'tcp.dstport',      # 5
        '-e', 'udp.dstport',      # 6
        '-e', 'frame.len',        # 7 (Total Len)
        '-e', 'tcp.len',          # 8 (Payload Len TCP)
        '-e', 'udp.length',       # 9 (Payload Len UDP - header)
        '-e', 'tcp.flags'         # 10
    ]

    try:
        # Run TShark
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        stdout, _ = process.communicate()

        # Parse output line by line
        for line in stdout.splitlines():
            cols = line.split(',')
            if len(cols) < 11: continue

            # Extract Raw Fields
            ts, src, dst, tcp_sport, udp_sport, tcp_dport, udp_dport, frame_len, tcp_len, udp_len, tcp_flags = cols

            # Logic to handle TCP vs UDP (TShark returns empty string for missing fields)
            if tcp_sport:
                sport = tcp_sport
                dport = tcp_dport
                proto = "TCP"
                payload = tcp_len if tcp_len else "0"
                # Flags (Hex to Int)
                try:
                    flags_int = int(tcp_flags, 16) if tcp_flags and tcp_flags.startswith('0x') else int(tcp_flags) if tcp_flags else 0
                except:
                    flags_int = 0
            elif udp_sport:
                sport = udp_sport
                dport = udp_dport
                proto = "UDP"
                # UDP length includes header (8 bytes), so payload is len - 8
                payload = str(max(0, int(udp_len) - 8)) if udp_len else "0"
                flags_int = 0
            else:
                continue

            # Determine Application Protocol Label
            app_proto = "Unknown"
            if sport in OT_PORTS: app_proto = OT_PORTS[sport]
            elif dport in OT_PORTS: app_proto = OT_PORTS[dport]
            else: app_proto = f"{proto}_Other"

            # Parse Flags
            syn = 1 if (flags_int & 0x02) else 0
            rst = 1 if (flags_int & 0x04) else 0
            fin = 1 if (flags_int & 0x01) else 0
            psh = 1 if (flags_int & 0x08) else 0
            ack = 1 if (flags_int & 0x10) else 0

            # Anonymize
            src_anon = anonymize_ip(src)
            dst_anon = anonymize_ip(dst)

            rows.append([
                ts, src_anon, dst_anon, sport, dport, app_proto, 
                payload, frame_len, syn, rst, fin, psh, ack
            ])
            
    except Exception as e:
        print(f"Error extracting {file_path}: {e}")
        
    return rows

def main():
    # Setup Output File
    headers = [
        "Timestamp_Epoch", "Src_IP_Anonymized", "Dst_IP_Anonymized", 
        "Src_Port", "Dst_Port", "Protocol", "Payload_Bytes", "Total_Packet_Len", 
        "TCP_SYN", "TCP_RST", "TCP_FIN", "TCP_PSH", "TCP_ACK"
    ]
    
    # Get file list
    all_files = [os.path.join(PCAP_FOLDER, f) for f in os.listdir(PCAP_FOLDER) if f.endswith('.pcap')]
    total_files = len(all_files)
    print(f" Starting Extraction on {total_files} files using {MAX_WORKERS} CPU cores...")
    
    start_time = time.time()
    
    with open(OUTPUT_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        # Parallel Execution
        with concurrent.futures.ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Map returns results in order
            for i, rows in enumerate(executor.map(process_single_file, all_files)):
                if rows:
                    writer.writerows(rows)
                
                if (i + 1) % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = (i + 1) / elapsed
                    print(f"Processed {i + 1}/{total_files} files ({rate:.2f} files/sec)...")

    print(f"✅ DONE! Total time: {time.time() - start_time:.2f} seconds.")

if __name__ == '__main__':
    main()