# PRE-test

## Protocol-Agnostic Structural Format Inference Tool

This repository provides a **protocol-agnostic, record-level structural format inference tool** that analyzes network packet captures (pcap files) to identify structural boundaries in unknown protocols.

### Features

- **TCP Reassembly**: Two-pass tshark analysis for complete stream reconstruction
- **Record Splitting**: Intelligent segmentation based on time gaps and size limits
- **Header Inference**: N-gram based value-stable anchor detection for structural boundary identification
- **Protocol-Agnostic**: No hardcoded protocol constants - works with any TCP-based protocol
- **Cross-Platform**: Works on Windows and Linux with automatic tshark detection

### Dependencies

#### Required
- **Python 3.7+**
- **Wireshark/tshark**: Network protocol analyzer
  - **Linux**: Install via package manager
    ```bash
    # Ubuntu/Debian
    sudo apt-get install tshark
    
    # Fedora/RHEL
    sudo dnf install wireshark-cli
    
    # Arch Linux
    sudo pacman -S wireshark-cli
    ```
  - **Windows**: Download and install [Wireshark](https://www.wireshark.org/download.html)
    - The tool will automatically detect tshark in standard installation paths
    - Or specify custom path with `--tshark` option

### Installation

Clone the repository:
```bash
git clone https://github.com/Maroon-hub/PRE-test.git
cd PRE-test
```

### Usage

#### Basic Usage

```bash
python3 tools/reverse_structural.py \
  --pcap-dir /path/to/pcaps \
  --port 502 \
  --out-dir ./output
```

#### All Options

```bash
python3 tools/reverse_structural.py \
  --pcap-dir <directory>       # Directory containing .pcap or .pcapng files
  --port <port_number>         # TCP port to analyze (e.g., 502 for Modbus)
  --out-dir <directory>        # Output directory for results
  [--tshark <path>]            # Optional: Path to tshark executable
  [--gap-ms <milliseconds>]    # Time gap for record splitting (default: 500)
  [--max-record-bytes <bytes>] # Max record size (default: 262144)
  [--header-max-bytes <bytes>] # Header window size (default: 64)
  [--slack <value>]            # Future extension parameter (default: 0)
```

#### Example Commands

**Analyze Modbus traffic:**
```bash
python3 tools/reverse_structural.py \
  --pcap-dir ./captures/modbus \
  --port 502 \
  --out-dir ./results/modbus
```

**Analyze DNP3 traffic with custom tshark path (Windows):**
```bash
python tools/reverse_structural.py \
  --pcap-dir C:\captures\dnp3 \
  --port 20000 \
  --out-dir C:\results\dnp3 \
  --tshark "C:\Program Files\Wireshark\tshark.exe"
```

**Custom record splitting parameters:**
```bash
python3 tools/reverse_structural.py \
  --pcap-dir ./captures \
  --port 102 \
  --gap-ms 1000 \
  --max-record-bytes 1024 \
  --header-max-bytes 128 \
  --out-dir ./results
```

### Output Files

The tool generates two output files in the specified `--out-dir`:

#### 1. `records.jsonl`
JSON Lines format containing one record per line. Each record includes:
- `pcap_file`: Source pcap filename
- `port`: Filtered TCP port
- `tcp_stream`: TCP stream ID from tshark
- `follow_dir`: Direction (0 or 1)
- `flow_id`: Flow identifier (src:port->dst:port)
- `record_id`: Sequential record ID within flow
- `t0`, `t1`: Start and end timestamps
- `raw_len`: Record length in bytes
- `sha256`: SHA-256 hash of raw bytes (raw bytes NOT included)
- `header_window_end`: End of header analysis window
- `boundaries`: List of inferred structural boundaries

**Example:**
```json
{"pcap_file": "capture.pcap", "port": 502, "tcp_stream": 0, "follow_dir": 0, "flow_id": "192.168.1.10:45678->192.168.1.20:502", "record_id": 0, "t0": 1234567890.123, "t1": 1234567890.125, "raw_len": 12, "sha256": "abc123...", "header_window_end": 12, "boundaries": [2, 6, 12]}
```

#### 2. `schema.json`
JSON format containing global structural inference:
- `meta`: Metadata about the analysis run
  - Tool version, parameters used, number of records/pcaps processed
- `global_boundaries`: List of inferred boundary positions across all records
- `segment_stats`: Per-segment statistics
  - `start`, `end`: Segment boundaries
  - `presence`: Proportion of records containing this segment (0.0-1.0)
  - `len_mean`, `len_std`: Mean and standard deviation of segment lengths
  - `entropy_mean`: Mean entropy metric for segment content

**Example:**
```json
{
  "meta": {
    "tool": "reverse_structural.py",
    "version": "1.0",
    "num_records": 150,
    "port": 502
  },
  "global_boundaries": [2, 6, 8],
  "segment_stats": [
    {"start": 0, "end": 2, "presence": 1.0, "len_mean": 2.0, "len_std": 0.0, "entropy_mean": 0.5},
    {"start": 2, "end": 6, "presence": 0.95, "len_mean": 4.0, "len_std": 0.2, "entropy_mean": 1.2}
  ]
}
```

### How It Works

1. **TCP Reassembly (Two-Pass tshark)**:
   - Pass 1: `follow,tcp,hex` (or `follow,tcp,raw` fallback) to get reassembled stream bytes
   - Pass 2: `-T fields` export to build per-direction packet timelines

2. **Direction Pairing**:
   - Matches follow directions with packet directions by comparing cumulative lengths

3. **Record Splitting**:
   - Splits streams into records based on time gaps (default 500ms)
   - Fallback to max-record-bytes limit (default 256KB)

4. **Structural Inference**:
   - Extracts N-gram anchors (sizes 1, 2, 3, 4) from header windows
   - Identifies value-stable anchors present in ≥60% of records
   - Filters by position stability (std ≤ 1.5)
   - Computes per-segment statistics for schema

5. **Output Generation**:
   - Records without raw bytes (SHA-256 hash only)
   - Global schema with boundary positions and statistics

### Adding to GitHub Project

After creating the pull request, add it to the GitHub Project manually:

1. Navigate to the [project board](https://github.com/users/Maroon-hub/projects/2)
2. Click the PR or issue you want to add
3. On the right sidebar, click the gear icon next to "Projects"
4. Select "Maroon-hub Project 2" from the list
5. The PR will now appear in the project board

**Note**: Programmatic addition via API requires project write permissions that may not be available to automated tools. Manual linking ensures proper project tracking.

### Troubleshooting

**"Cannot run tshark" error:**
- Verify Wireshark/tshark is installed: `tshark -v`
- On Windows, specify full path: `--tshark "C:\Program Files\Wireshark\tshark.exe"`
- On Linux, ensure tshark is in PATH or install via package manager

**No records extracted:**
- Verify pcap files contain TCP traffic on the specified port
- Check pcap files are valid: `tshark -r <file.pcap>`
- Ensure the port filter matches your protocol's port

**Empty boundaries:**
- Increase `--header-max-bytes` to analyze larger headers
- Try different `--gap-ms` values for better record splitting
- May indicate very diverse traffic with no stable patterns

### License

See repository license file for details.