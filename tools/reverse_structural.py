#!/usr/bin/env python3
"""
Protocol-agnostic, record-level structural format inference tool.

This tool performs TCP reassembly via two-pass tshark, splits records by time gaps,
and infers structural boundaries using N-gram value-stable anchors in header windows.
"""

import argparse
import hashlib
import json
import math
import os
import platform
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
import statistics


@dataclass
class Packet:
    """Represents a single TCP packet."""
    tcp_stream: int
    frame_time: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    tcp_len: int


@dataclass
class Direction:
    """Represents one direction of a TCP stream."""
    tcp_stream: int
    follow_dir: int  # 0 or 1 from follow output
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packets: List[Packet] = field(default_factory=list)
    reassembled_bytes: bytes = b''
    
    @property
    def flow_id(self) -> str:
        """Generate flow identifier."""
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}"


@dataclass
class Record:
    """Represents a single protocol record."""
    pcap_file: str
    port: int
    tcp_stream: int
    follow_dir: int
    flow_id: str
    record_id: int
    t0: float
    t1: float
    raw_len: int
    sha256: str
    header_window_end: int
    boundaries: List[int]


@dataclass
class Anchor:
    """N-gram anchor with position and stability metrics."""
    ngram: bytes
    positions: List[int]
    
    @property
    def mean_pos(self) -> float:
        return statistics.mean(self.positions) if self.positions else 0.0
    
    @property
    def std_pos(self) -> float:
        return statistics.stdev(self.positions) if len(self.positions) > 1 else 0.0


def find_tshark() -> str:
    """Locate tshark executable on the system."""
    system = platform.system()
    
    # Common paths for Windows
    if system == 'Windows':
        common_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path
    
    # Try PATH on all systems
    try:
        result = subprocess.run(['which', 'tshark'], 
                              capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    
    # Last resort: assume it's in PATH
    return 'tshark'


def run_tshark_follow(pcap_path: str, tshark_cmd: str, stream_id: int, 
                      use_raw: bool = False) -> Dict[int, bytes]:
    """
    Run tshark with follow,tcp,hex (or raw) to get reassembled stream bytes.
    
    Returns dict mapping follow_dir (0 or 1) to reassembled bytes.
    """
    follow_type = 'raw' if use_raw else 'hex'
    cmd = [
        tshark_cmd, '-r', pcap_path,
        '-q', '-z', f'follow,tcp,{follow_type},{stream_id}'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, 
                              check=True, timeout=300)
    except subprocess.CalledProcessError as e:
        print(f"Warning: tshark follow failed for stream {stream_id}: {e}", 
              file=sys.stderr)
        return {}
    except subprocess.TimeoutExpired:
        print(f"Warning: tshark follow timeout for stream {stream_id}", 
              file=sys.stderr)
        return {}
    
    return parse_follow_output(result.stdout, use_raw)


def parse_follow_output(output: str, is_raw: bool) -> Dict[int, bytes]:
    """
    Parse tshark follow output to extract reassembled bytes per direction.
    
    Format for hex:
    ===================================================================
    Follow: tcp,hex
    Filter: tcp.stream eq 0
    Node 0: 192.168.1.1:1234
    Node 1: 192.168.1.2:5678
    	00000000  48 65 6c 6c 6f                                   Hello
    	00000005  20 57 6f 72 6c 64                                 World
    ...
    
    Format for raw (similar but with raw ASCII in right column).
    
    Note: The actual format shows Node declarations first, then data for the
    first direction starts. When a "Node X:\nNode Y:" line appears, it indicates
    a direction switch.
    """
    directions = {}
    current_dir = 0  # Start with direction 0
    current_bytes = bytearray()
    seen_data = False
    
    lines = output.split('\n')
    i = 0
    
    while i < len(lines):
        line = lines[i]
        line_stripped = line.strip()
        
        # Check for tab-indented hex data lines
        if line.startswith('\t') and len(line_stripped) > 8:
            seen_data = True
            # Parse hex line: "00000000  48 65 6c 6c 6f ..."
            parts = line_stripped.split(None, 1)
            if len(parts) >= 2:
                offset_str = parts[0]
                hex_and_ascii = parts[1]
                
                # Extract hex bytes (everything before ASCII representation)
                # Look for multiple spaces indicating ASCII section
                hex_part = hex_and_ascii
                if '  ' in hex_and_ascii:
                    hex_part = hex_and_ascii.split('  ')[0]
                
                # Parse hex bytes
                hex_bytes = hex_part.split()
                for hb in hex_bytes:
                    if len(hb) == 2 and all(c in '0123456789abcdefABCDEF' for c in hb):
                        current_bytes.append(int(hb, 16))
        
        # Check for direction change: "Node X:\nNode Y:" pattern after data has started
        elif line_stripped.startswith('Node ') and seen_data:
            # Check if next line is also "Node X:"
            if i + 1 < len(lines) and lines[i + 1].strip().startswith('Node '):
                # Save current direction
                if current_bytes:
                    directions[current_dir] = bytes(current_bytes)
                    current_bytes = bytearray()
                
                # Switch to next direction
                current_dir = 1 if current_dir == 0 else 0
                i += 1  # Skip the next "Node X:" line
        
        i += 1
    
    # Save final direction
    if current_bytes:
        directions[current_dir] = bytes(current_bytes)
    
    return directions


def run_tshark_fields(pcap_path: str, tshark_cmd: str, port_filter: int) -> List[Packet]:
    """
    Run tshark with -T fields to extract packet timeline information.
    
    Exports: tcp.stream, frame.time_epoch, ip.src, tcp.srcport, ip.dst, tcp.dstport, tcp.len
    """
    cmd = [
        tshark_cmd, '-r', pcap_path, '-Y', f'tcp.port == {port_filter}',
        '-T', 'fields',
        '-e', 'tcp.stream',
        '-e', 'frame.time_epoch',
        '-e', 'ip.src',
        '-e', 'tcp.srcport',
        '-e', 'ip.dst',
        '-e', 'tcp.dstport',
        '-e', 'tcp.len',
        '-E', 'separator=|'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, 
                              check=True, timeout=300)
    except subprocess.CalledProcessError as e:
        print(f"Warning: tshark fields failed: {e}", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print(f"Warning: tshark fields timeout", file=sys.stderr)
        return []
    
    packets = []
    for line in result.stdout.strip().split('\n'):
        if not line:
            continue
        
        parts = line.split('|')
        if len(parts) != 7:
            continue
        
        try:
            packet = Packet(
                tcp_stream=int(parts[0]),
                frame_time=float(parts[1]),
                src_ip=parts[2],
                src_port=int(parts[3]),
                dst_ip=parts[4],
                dst_port=int(parts[5]),
                tcp_len=int(parts[6]) if parts[6] else 0
            )
            packets.append(packet)
        except (ValueError, IndexError):
            continue
    
    return packets


def pair_directions(follow_data: Dict[int, bytes], packets: List[Packet], 
                   tcp_stream: int) -> List[Direction]:
    """
    Pair follow directions with packet directions by matching cumulative lengths.
    
    Returns a list of Direction objects with reassembled bytes and packet timeline.
    """
    # Group packets by direction (src -> dst)
    packet_dirs: Dict[Tuple[str, int, str, int], List[Packet]] = defaultdict(list)
    
    for pkt in packets:
        if pkt.tcp_stream == tcp_stream:
            key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
            packet_dirs[key].append(pkt)
    
    # Calculate cumulative lengths for each packet direction
    dir_cum_lens: Dict[Tuple, int] = {}
    for key, pkts in packet_dirs.items():
        dir_cum_lens[key] = sum(p.tcp_len for p in pkts)
    
    # Match follow directions to packet directions by closest length
    directions = []
    used_keys = set()
    
    for follow_dir, follow_bytes in sorted(follow_data.items()):
        follow_len = len(follow_bytes)
        
        # Find closest packet direction by cumulative length
        best_key = None
        best_diff = float('inf')
        
        for key, cum_len in dir_cum_lens.items():
            if key in used_keys:
                continue
            
            diff = abs(follow_len - cum_len)
            if diff < best_diff:
                best_diff = diff
                best_key = key
        
        if best_key:
            used_keys.add(best_key)
            src_ip, src_port, dst_ip, dst_port = best_key
            
            direction = Direction(
                tcp_stream=tcp_stream,
                follow_dir=follow_dir,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                packets=sorted(packet_dirs[best_key], key=lambda p: p.frame_time),
                reassembled_bytes=follow_bytes
            )
            directions.append(direction)
    
    return directions


def split_records(direction: Direction, gap_ms: float, 
                 max_record_bytes: int) -> List[Tuple[bytes, float, float]]:
    """
    Split reassembled bytes into records based on time gaps and max size.
    
    Returns list of (record_bytes, t0, t1) tuples.
    """
    if not direction.packets or not direction.reassembled_bytes:
        return []
    
    records = []
    current_start = 0
    current_t0 = direction.packets[0].frame_time
    current_t1 = current_t0
    last_time = current_t0
    
    cumulative_len = 0
    
    for pkt in direction.packets:
        pkt_len = pkt.tcp_len
        if pkt_len == 0:
            continue
        
        # Check time gap
        time_gap = (pkt.frame_time - last_time) * 1000  # Convert to ms
        
        # Check if we should split
        should_split = False
        if time_gap > gap_ms:
            should_split = True
        elif cumulative_len + pkt_len > max_record_bytes:
            should_split = True
        
        if should_split and cumulative_len > 0:
            # Extract record bytes
            record_bytes = direction.reassembled_bytes[current_start:current_start + cumulative_len]
            if record_bytes:
                records.append((record_bytes, current_t0, current_t1))
            
            # Start new record
            current_start += cumulative_len
            current_t0 = pkt.frame_time
            cumulative_len = 0
        
        cumulative_len += pkt_len
        current_t1 = pkt.frame_time
        last_time = pkt.frame_time
    
    # Add final record
    if cumulative_len > 0:
        record_bytes = direction.reassembled_bytes[current_start:current_start + cumulative_len]
        if record_bytes:
            records.append((record_bytes, current_t0, current_t1))
    
    return records


def extract_ngrams(data: bytes, n: int, max_start: int) -> Dict[bytes, List[int]]:
    """
    Extract all n-grams from data within max_start window.
    
    Returns dict mapping n-gram to list of start positions.
    """
    ngrams: Dict[bytes, List[int]] = defaultdict(list)
    
    for i in range(min(len(data), max_start) - n + 1):
        ngram = data[i:i+n]
        ngrams[ngram].append(i)
    
    return dict(ngrams)


def find_stable_anchors(records_bytes: List[bytes], ns: List[int], theta: float,
                       eps_std: float, max_start: int, merge_gap: int) -> List[int]:
    """
    Find value-stable anchors across multiple records.
    
    Parameters:
    - records_bytes: List of record byte sequences
    - ns: N-gram sizes to consider (e.g., [1, 2, 3, 4])
    - theta: Minimum presence ratio (e.g., 0.6 = present in 60% of records)
    - eps_std: Maximum standard deviation for position stability
    - max_start: Maximum start position to consider (header window)
    - merge_gap: Gap for merging adjacent anchors (0 = no merging)
    
    Returns: List of boundary positions (anchor ends)
    """
    if not records_bytes:
        return []
    
    num_records = len(records_bytes)
    min_presence = int(num_records * theta)
    
    # Collect candidate anchors
    candidates: Dict[Tuple[bytes, int], Anchor] = {}
    
    for n in ns:
        # Extract n-grams from all records
        for record_bytes in records_bytes:
            ngrams = extract_ngrams(record_bytes, n, max_start)
            
            for ngram, positions in ngrams.items():
                # Use first position in each record
                pos = positions[0]
                key = (ngram, n)
                
                if key not in candidates:
                    candidates[key] = Anchor(ngram=ngram, positions=[])
                
                candidates[key].positions.append(pos)
    
    # Filter by presence and stability
    stable_anchors = []
    for key, anchor in candidates.items():
        if len(anchor.positions) < min_presence:
            continue
        
        if len(anchor.positions) > 1 and anchor.std_pos > eps_std:
            continue
        
        # Anchor end position = mean_pos + len(ngram)
        anchor_end = int(anchor.mean_pos) + len(anchor.ngram)
        stable_anchors.append(anchor_end)
    
    # Remove duplicates and sort
    boundaries = sorted(set(stable_anchors))
    
    # Merge adjacent boundaries if merge_gap > 0
    if merge_gap > 0 and len(boundaries) > 1:
        merged = [boundaries[0]]
        for b in boundaries[1:]:
            if b - merged[-1] <= merge_gap:
                merged[-1] = b  # Keep the larger one
            else:
                merged.append(b)
        boundaries = merged
    
    return boundaries


def infer_boundaries(records_bytes: List[bytes], header_max_bytes: int) -> List[int]:
    """
    Infer structural boundaries using N-gram anchors.
    
    Uses parameters from spec:
    - ns = (1, 2, 3, 4)
    - theta = 0.6
    - eps_std = 1.5
    - max_start = header_max_bytes
    - merge_gap = 0
    """
    ns = [1, 2, 3, 4]
    theta = 0.6
    eps_std = 1.5
    merge_gap = 0
    
    global_boundaries = find_stable_anchors(
        records_bytes, ns, theta, eps_std, header_max_bytes, merge_gap
    )
    
    return global_boundaries


def compute_segment_stats(records_bytes: List[bytes], boundaries: List[int]) -> List[Dict]:
    """
    Compute per-segment statistics: presence, len_mean/std, entropy_mean.
    
    A segment is defined by consecutive boundaries.
    """
    if not boundaries:
        return []
    
    # Create segments from boundaries
    segments = []
    for i in range(len(boundaries)):
        start = boundaries[i-1] if i > 0 else 0
        end = boundaries[i]
        segments.append((start, end))
    
    stats = []
    for start, end in segments:
        segment_data = []
        
        for record_bytes in records_bytes:
            if len(record_bytes) > start:
                segment = record_bytes[start:min(end, len(record_bytes))]
                if segment:
                    segment_data.append(segment)
        
        if not segment_data:
            stats.append({
                'start': start,
                'end': end,
                'presence': 0.0,
                'len_mean': 0.0,
                'len_std': 0.0,
                'entropy_mean': 0.0
            })
            continue
        
        presence = len(segment_data) / len(records_bytes)
        lengths = [len(seg) for seg in segment_data]
        len_mean = statistics.mean(lengths)
        len_std = statistics.stdev(lengths) if len(lengths) > 1 else 0.0
        
        # Compute entropy (simplified: byte value distribution)
        entropies = []
        for seg in segment_data:
            byte_counts = defaultdict(int)
            for b in seg:
                byte_counts[b] += 1
            
            total = len(seg)
            entropy = 0.0
            for count in byte_counts.values():
                p = count / total
                if p > 0:
                    entropy -= p * math.log2(p)  # Shannon entropy
            
            entropies.append(entropy)
        
        entropy_mean = statistics.mean(entropies) if entropies else 0.0
        
        stats.append({
            'start': start,
            'end': end,
            'presence': round(presence, 3),
            'len_mean': round(len_mean, 2),
            'len_std': round(len_std, 2),
            'entropy_mean': round(entropy_mean, 3)
        })
    
    return stats


def process_pcap(pcap_path: str, port: int, tshark_cmd: str, gap_ms: float,
                max_record_bytes: int, header_max_bytes: int) -> Tuple[List[Record], List[bytes]]:
    """
    Process a single pcap file and extract records.
    
    Returns (records, all_records_bytes) for later schema inference.
    """
    pcap_name = os.path.basename(pcap_path)
    print(f"Processing {pcap_name}...")
    
    # Pass 2 (fields) - get packet timeline
    packets = run_tshark_fields(pcap_path, tshark_cmd, port)
    if not packets:
        print(f"  No packets found for port {port}")
        return [], []
    
    # Get unique TCP streams
    tcp_streams = sorted(set(p.tcp_stream for p in packets))
    print(f"  Found {len(tcp_streams)} TCP stream(s)")
    
    all_records = []
    all_records_bytes = []
    
    for tcp_stream in tcp_streams:
        # Pass 1 (follow) - get reassembled bytes
        follow_data = run_tshark_follow(pcap_path, tshark_cmd, tcp_stream, use_raw=False)
        
        # Fallback to raw if hex fails
        if not follow_data:
            follow_data = run_tshark_follow(pcap_path, tshark_cmd, tcp_stream, use_raw=True)
        
        if not follow_data:
            print(f"  No follow data for stream {tcp_stream}")
            continue
        
        # Pair directions
        directions = pair_directions(follow_data, packets, tcp_stream)
        
        for direction in directions:
            if not direction.reassembled_bytes:
                continue
            
            # Split into records
            record_tuples = split_records(direction, gap_ms, max_record_bytes)
            
            for record_id, (record_bytes, t0, t1) in enumerate(record_tuples):
                # Compute header window end (min of header_max_bytes or record length)
                header_window_end = min(header_max_bytes, len(record_bytes))
                
                # Create record (boundaries will be added later)
                record = Record(
                    pcap_file=pcap_name,
                    port=port,
                    tcp_stream=tcp_stream,
                    follow_dir=direction.follow_dir,
                    flow_id=direction.flow_id,
                    record_id=record_id,
                    t0=t0,
                    t1=t1,
                    raw_len=len(record_bytes),
                    sha256=hashlib.sha256(record_bytes).hexdigest(),
                    header_window_end=header_window_end,
                    boundaries=[]  # Will be filled after global inference
                )
                
                all_records.append(record)
                all_records_bytes.append(record_bytes)
    
    print(f"  Extracted {len(all_records)} record(s)")
    return all_records, all_records_bytes


def main():
    parser = argparse.ArgumentParser(
        description='Protocol-agnostic structural format inference tool'
    )
    parser.add_argument('--pcap-dir', required=True,
                       help='Directory containing pcap files')
    parser.add_argument('--port', type=int, required=True,
                       help='TCP port to filter')
    parser.add_argument('--tshark', default=None,
                       help='Path to tshark executable (auto-detected if not provided)')
    parser.add_argument('--gap-ms', type=float, default=500.0,
                       help='Time gap in milliseconds for record splitting (default: 500)')
    parser.add_argument('--max-record-bytes', type=int, default=262144,
                       help='Maximum bytes per record (default: 262144)')
    parser.add_argument('--header-max-bytes', type=int, default=64,
                       help='Maximum header window size in bytes (default: 64)')
    parser.add_argument('--slack', type=int, default=0,
                       help='Additional slack parameter (currently unused, for future extension)')
    parser.add_argument('--out-dir', required=True,
                       help='Output directory for results')
    
    args = parser.parse_args()
    
    # Find tshark
    tshark_cmd = args.tshark if args.tshark else find_tshark()
    print(f"Using tshark: {tshark_cmd}")
    
    # Verify tshark is available
    try:
        subprocess.run([tshark_cmd, '-v'], capture_output=True, check=True, timeout=10)
    except Exception as e:
        print(f"Error: Cannot run tshark: {e}", file=sys.stderr)
        print("Please install Wireshark/tshark or specify path with --tshark", file=sys.stderr)
        return 1
    
    # Find pcap files
    pcap_dir = Path(args.pcap_dir)
    if not pcap_dir.is_dir():
        print(f"Error: {args.pcap_dir} is not a directory", file=sys.stderr)
        return 1
    
    pcap_files = list(pcap_dir.glob('*.pcap')) + list(pcap_dir.glob('*.pcapng'))
    if not pcap_files:
        print(f"Warning: No pcap files found in {args.pcap_dir}", file=sys.stderr)
    
    print(f"Found {len(pcap_files)} pcap file(s)")
    
    # Process all pcaps
    all_records = []
    all_records_bytes = []
    
    for pcap_path in pcap_files:
        records, records_bytes = process_pcap(
            str(pcap_path), args.port, tshark_cmd,
            args.gap_ms, args.max_record_bytes, args.header_max_bytes
        )
        all_records.extend(records)
        all_records_bytes.extend(records_bytes)
    
    if not all_records:
        print("No records extracted from any pcap file")
        return 1
    
    print(f"\nTotal records extracted: {len(all_records)}")
    
    # Infer global boundaries
    print("Inferring structural boundaries...")
    global_boundaries = infer_boundaries(all_records_bytes, args.header_max_bytes)
    print(f"Found {len(global_boundaries)} global boundaries")
    
    # Assign boundaries to each record
    for record, record_bytes in zip(all_records, all_records_bytes):
        # Union of global boundaries within record length, header_window_end, and record end
        boundaries = set()
        
        for b in global_boundaries:
            if b <= len(record_bytes):
                boundaries.add(b)
        
        boundaries.add(record.header_window_end)
        boundaries.add(len(record_bytes))
        
        record.boundaries = sorted(boundaries)
    
    # Compute segment statistics
    print("Computing segment statistics...")
    segment_stats = compute_segment_stats(all_records_bytes, global_boundaries)
    
    # Create output directory
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Write records.jsonl (without raw bytes)
    records_path = out_dir / 'records.jsonl'
    with open(records_path, 'w') as f:
        for record in all_records:
            record_dict = {
                'pcap_file': record.pcap_file,
                'port': record.port,
                'tcp_stream': record.tcp_stream,
                'follow_dir': record.follow_dir,
                'flow_id': record.flow_id,
                'record_id': record.record_id,
                't0': record.t0,
                't1': record.t1,
                'raw_len': record.raw_len,
                'sha256': record.sha256,
                'header_window_end': record.header_window_end,
                'boundaries': record.boundaries
            }
            f.write(json.dumps(record_dict) + '\n')
    
    print(f"Wrote {records_path}")
    
    # Write schema.json
    schema = {
        'meta': {
            'tool': 'reverse_structural.py',
            'version': '1.0',
            'pcap_dir': str(pcap_dir),
            'port': args.port,
            'gap_ms': args.gap_ms,
            'max_record_bytes': args.max_record_bytes,
            'header_max_bytes': args.header_max_bytes,
            'num_records': len(all_records),
            'num_pcaps': len(pcap_files)
        },
        'global_boundaries': global_boundaries,
        'segment_stats': segment_stats
    }
    
    schema_path = out_dir / 'schema.json'
    with open(schema_path, 'w') as f:
        json.dump(schema, f, indent=2)
    
    print(f"Wrote {schema_path}")
    print("\nDone!")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
