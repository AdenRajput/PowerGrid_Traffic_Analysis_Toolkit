import subprocess
import os
import csv
import json
import concurrent.futures
import time

# --- CONFIGURATION ---
PCAP_FOLDER = r"./input_pcaps/"
OUTPUT_CSV = "S2_Electricity_Data.csv"
STATION_LABEL = "S2"
MAX_WORKERS = os.cpu_count()

def parse_topic(topic_str):
    """Splits topic string into Asset and Measurement Type."""
    parts = topic_str.split('/')
    if len(parts) >= 5:
        measure_type = parts[-1] 
        asset = "/".join(parts[2:-1]) 
        return asset, measure_type
    return "Unknown", "Unknown"

def process_single_file(file_path):
    rows = []
    
    # TShark Command: Extract Time, Topic, and Payload (msg)
    # -Y mqtt: Filter for MQTT only
    # -T fields: Output text, not pcap
    cmd = [
        'tshark', '-n', '-r', file_path,
        '-Y', 'mqtt.msg', 
        '-T', 'fields',
        '-E', 'separator=|',
        '-e', 'frame.time_epoch',
        '-e', 'mqtt.topic',
        '-e', 'mqtt.msg'
    ]

    try:
        # Run TShark
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='ignore')
        stdout, _ = process.communicate()

        for line in stdout.splitlines():
            try:
                # 1. Split TShark Output
                parts = line.strip().split('|')
                if len(parts) < 3: continue
                
                ts_capture = parts[0]
                raw_topic = parts[1]
                payload_hex = parts[2].replace(':', '')
                
                # 2. Decode Payload (Hex -> String -> JSON)
                try:
                    payload_str = bytes.fromhex(payload_hex).decode('utf-8')
                    data = json.loads(payload_str)
                except:
                    continue 
                
                # 3. Extract Data Fields
                val = data.get('v', '')
                quality = data.get('q', '')
                ts_device = data.get('t', '')
                sig_id = data.get('id', '')
                
                # Fallback if device time is missing
                if not ts_device: ts_device = ts_capture
                
                # 4. Parse Topic (Anonymize & Structure)
                asset, m_type = parse_topic(raw_topic)
                
                # 5. Append Row
                rows.append([
                    ts_device, ts_capture, STATION_LABEL, 
                    asset, m_type, val, quality, sig_id
                ])
                
            except Exception:
                continue

    except Exception as e:
        print(f"Error file {file_path}: {e}")
        
    return rows

def main():
    headers = [
        "Timestamp_Device", "Timestamp_Capture", "Station_Label",
        "Asset_ID", "Measurement_Type", "Value", "Quality_Bit", "Signal_ID"
    ]
    
    files = [os.path.join(PCAP_FOLDER, f) for f in os.listdir(PCAP_FOLDER) if f.endswith('.pcap')]
    total_files = len(files)
    print(f"Starting  MQTT Extraction for {STATION_LABEL} on {total_files} files...")
    
    start_time = time.time()
    
    with open(OUTPUT_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        with concurrent.futures.ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for i, result_rows in enumerate(executor.map(process_single_file, files)):
                if result_rows:
                    writer.writerows(result_rows)
                
                if (i + 1) % 100 == 0:
                    rate = (i + 1) / (time.time() - start_time)
                    print(f"Processed {i + 1}/{total_files} files ({rate:.1f} files/sec)...", end='\r')

    print(f"\n✅ DONE! Data saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()