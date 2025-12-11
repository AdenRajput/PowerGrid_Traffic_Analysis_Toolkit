import pandas as pd
import sys
import warnings

# --- CONFIGURATION ---
CSV_FILE = "0" #csv path here 
CHUNK_SIZE = 1000000 # Increased to 1M for speed
REPORT_FILE = "Audit_Report.txt"

def audit_data_chunked():
    # 1. SILENCE THE WARNINGS (Crucial for Speed/Stability)
    warnings.filterwarnings("ignore", category=UserWarning)
    
    print(f"--- AUDITING S3 (SILENT MODE) ---")
    print(f"Output will be saved to: {REPORT_FILE}")
    
    total_rows = 0
    syn_count = 0
    rst_count = 0
    protocols = {}
    
    # Open report file immediately to ensure we can write
    with open(REPORT_FILE, "w") as f:
        f.write(f"--- AUDIT REPORT FOR {CSV_FILE} ---\n")
    
    try:
        # Process in chunks
        for i, chunk in enumerate(pd.read_csv(CSV_FILE, chunksize=CHUNK_SIZE)):
            
            # 1. Update Counts
            total_rows += len(chunk)
            syn_count += chunk['TCP_SYN'].sum()
            rst_count += chunk['TCP_RST'].sum()
            
            # 2. Protocol Distribution
            proto_counts = chunk['Protocol'].value_counts()
            for proto, count in proto_counts.items():
                protocols[proto] = protocols.get(proto, 0) + count
            
            # 3. Privacy Check (Optimized Regex)
            # using '?:' to avoid the capture group warning logic entirely
            leaks = chunk[chunk['Src_IP_Anonymized'].str.contains(r'^(?:192\.|10\.|172\.)', regex=True, na=False)]
            if not leaks.empty:
                msg = f"🚨 CRITICAL FAIL: Real IPs detected in rows {total_rows - len(chunk)} to {total_rows}!"
                print(msg)
                with open(REPORT_FILE, "a") as f: f.write(msg + "\n")
                return

            # Progress Indicator (Only print every 5 million rows to save UI)
            if i % 5 == 0:
                print(f"Processed {total_rows:,} rows...", end='\r')

    except Exception as e:
        print(f"\nCRITICAL FAIL: {e}")
        return

    # --- COMPILE FINAL REPORT ---
    report_lines = [
        f"\n\n--- FINAL RESULTS ---",
        f"Total Packets Processed: {total_rows:,}",
        f"Protocol Distribution:",
    ]
    
    for p, c in protocols.items():
        report_lines.append(f"  - {p}: {c:,}")
        
    report_lines.append(f"Total SYN Flags: {syn_count:,}")
    report_lines.append(f"Total RST Flags: {rst_count:,}")
    
    if syn_count > 0:
        report_lines.append("PASS: Connection flags present.")
    else:
        report_lines.append("WARNING: No SYN flags found.")
        
    report_lines.append("PASS: No Privacy Leaks Detected.")
    report_lines.append(f"--- END OF REPORT ---")
    
    # Print to Console
    full_report = "\n".join(report_lines)
    print(full_report)
    
    # Save to File (The Safety Net)
    with open(REPORT_FILE, "a") as f:
        f.write(full_report)
        
    print(f"\nReport saved to {REPORT_FILE}")

if __name__ == "__main__":
    audit_data_chunked()