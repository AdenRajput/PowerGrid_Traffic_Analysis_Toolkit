import subprocess
import os
import pandas as pd
import concurrent.futures
import time

# --- CONFIGURATION: UPDATE FOR EACH STATION ---
PCAP_FOLDER = r"./data/"
OUTPUT_CSV = "Book1.csv" #book1 fro s1
MAX_WORKERS = os.cpu_count() 

def get_file_times(file_path):
    """
    Extracts the Start and End timestamp of a PCAP file using TShark.
    Returns: (filename, start_epoch, end_epoch)
    """
    filename = os.path.basename(file_path)
    try:
        # Get Start Time (First Packet)
        cmd_start = ['tshark', '-r', file_path, '-c', '1', '-T', 'fields', '-e', 'frame.time_epoch']
        proc_start = subprocess.run(cmd_start, capture_output=True, text=True)
        start_ts = float(proc_start.stdout.strip())

        # Get End Time (Last Packet) - using capinfos is faster for end time usually, 
        # but tshark tail logic is consistent with your previous work.
        # Efficient TShark Tail: Read only headers (-n), minimal output
        # NOTE: 'tail' is not native to Windows TShark, so we read all timestamps and take the last.
        # For speed, we use capinfos if available, otherwise tshark. 
        # Let's stick to the method that allows reading the last packet reliable via TShark pipeline (slower but robust) 
        # OR use 'capinfos' which is installed with Wireshark and is instant.
        
        # METHOD B: CAPINFOS (Preferred for speed)
        cmd_cap = ['capinfos', '-T', '-r', '-a', '-e', file_path]
        proc_cap = subprocess.run(cmd_cap, capture_output=True, text=True)
        # Output: "File path" "Start" "End"
        parts = proc_cap.stdout.strip().split('\t')
        if len(parts) >= 3:
            return filename, float(parts[1]), float(parts[2])
        
        # Fallback if capinfos fails
        return filename, start_ts, start_ts # Fail safe
        
    except Exception as e:
        return filename, None, None

def main():
    print(f"--- CONTINUITY CHECK: {PCAP_FOLDER} ---")
    
    # 1. Get File List
    files = [os.path.join(PCAP_FOLDER, f) for f in os.listdir(PCAP_FOLDER) if f.endswith('.pcap')]
    print(f"Found {len(files)} files. Extracting time boundaries...")
    
    data = []
    start_time = time.time()
    
    # 2. Extract Times (Parallel)
    with concurrent.futures.ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(get_file_times, f): f for f in files}
        
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            fname, t_start, t_end = future.result()
            if t_start is not None:
                data.append({'FileName': fname, 'T_Start': t_start, 'T_End': t_end})
            
            if (i + 1) % 100 == 0:
                print(f"Processed {i + 1}/{len(files)}...", end='\r')

    print(f"\nExtraction done in {time.time() - start_time:.2f}s.")
    
    # 3. Create DataFrame & Sort (The "True" Chronology)
    df = pd.DataFrame(data)
    df = df.sort_values(by='T_Start').reset_index(drop=True)
    
    # 4. Calculate Duration and Gap
    # Duration = End - Start
    df['Duration_Seconds'] = df['T_End'] - df['T_Start']
    
    # Gap = Start(Next File) - End(Current File)
    df['Prev_End'] = df['T_End'].shift(1)
    df['True_Gap_Seconds'] = df['T_Start'] - df['Prev_End']
    
    # 5. Save & Report
    df.to_csv(OUTPUT_CSV, index=False)
    print(f" Saved analysis to {OUTPUT_CSV}")
    
    # Quick Stats
    gaps = df[df['True_Gap_Seconds'] > 1.0]
    overlaps = df[df['True_Gap_Seconds'] < -1.0]
    
    print("\n--- REPORT SUMMARY ---")
    print(f"Total Files: {len(df)}")
    print(f"Continuity Score (>1s Gap): {100 - (len(gaps)/len(df)*100):.2f}%")
    print(f"Major Gaps (>1s): {len(gaps)}")
    print(f"Overlaps (<-1s):  {len(overlaps)}")
    print("-" * 30)
    print("Top 5 Largest Gaps:")
    print(gaps.nlargest(5, 'True_Gap_Seconds')[['FileName', 'True_Gap_Seconds']])

if __name__ == '__main__':
    main()