# Power Grid Traffic Analysis Toolkit

This repository contains the source code used to curate and validate the **Electra-Grid** cyber-physical dataset. 
These scripts provide a reproducible pipeline for extracting packet-level network features and decoding MQTT process telemetry from raw PCAP files.

## Repository Structure

* **`extraction_scripts/`**: 
    * `extract_network_packets.py`: TShark-based extractor for network flows (IEC-104, MQTT, SNMP).
    * `extract_mqtt_physics.py`: JSON payload decoder for extracting electrical measurements (Voltage, Current, Power).
* **`validation_scripts/`**:
    * `check_continuity.py`: Forensically verifies temporal continuity of capture files.
    * `audit_network_quality.py`: Audits CSVs for privacy leaks and protocol distribution.
* **`visualization_scripts/`**:
    * Code to generate the continuity and synchronization figures used in the paper.

## Usage

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *Note: Wireshark/TShark must be installed and added to the system PATH.*

2.  **Configuration:**
    * Update the `PCAP_FOLDER` variable in the scripts to point to your data directory.
    * Set a private `SALT` string in the extraction scripts to ensure consistent anonymization.

## License
MIT License