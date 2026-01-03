#!/usr/bin/env python3
"""
Unit tests for reverse_structural.py core functions.
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from reverse_structural import (
    parse_follow_output,
    extract_ngrams,
    find_stable_anchors,
    compute_segment_stats
)


class TestParseFollowOutput(unittest.TestCase):
    """Test tshark follow output parsing."""
    
    def test_parse_hex_output(self):
        """Test parsing hex follow output."""
        output = """===================================================================
Follow: tcp,hex
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:5678
\t00000000  48 65 6c 6c 6f                                   Hello
\t00000005  20 57 6f 72 6c 64                                 World
"""
        result = parse_follow_output(output, is_raw=False)
        self.assertIn(0, result)
        self.assertEqual(result[0], b'Hello World')
    
    def test_parse_two_directions(self):
        """Test parsing with both directions."""
        output = """===================================================================
Follow: tcp,hex
Filter: tcp.stream eq 0
Node 0: 192.168.1.1:1234
Node 1: 192.168.1.2:5678
\t00000000  41 42                                            AB
Node 1: 192.168.1.2:5678
Node 0: 192.168.1.1:1234
\t00000000  43 44                                            CD
"""
        result = parse_follow_output(output, is_raw=False)
        self.assertEqual(len(result), 2)
        self.assertIn(0, result)
        self.assertIn(1, result)
        self.assertEqual(result[0], b'AB')
        self.assertEqual(result[1], b'CD')


class TestNGramExtraction(unittest.TestCase):
    """Test N-gram extraction."""
    
    def test_extract_1grams(self):
        """Test extracting 1-grams."""
        data = b'ABCABC'
        ngrams = extract_ngrams(data, 1, max_start=10)
        self.assertIn(b'A', ngrams)
        self.assertIn(b'B', ngrams)
        self.assertIn(b'C', ngrams)
        self.assertEqual(ngrams[b'A'], [0, 3])
        self.assertEqual(ngrams[b'B'], [1, 4])
    
    def test_extract_2grams(self):
        """Test extracting 2-grams."""
        data = b'ABABC'
        ngrams = extract_ngrams(data, 2, max_start=10)
        self.assertIn(b'AB', ngrams)
        self.assertEqual(ngrams[b'AB'], [0, 2])
    
    def test_max_start_limit(self):
        """Test that max_start limits extraction window."""
        data = b'ABCDEFGHIJ'
        ngrams = extract_ngrams(data, 1, max_start=5)
        # Should only extract from first 5 bytes
        self.assertIn(b'A', ngrams)
        self.assertIn(b'E', ngrams)
        self.assertNotIn(b'F', ngrams)


class TestStableAnchors(unittest.TestCase):
    """Test stable anchor detection."""
    
    def test_find_stable_anchors_simple(self):
        """Test finding stable anchors in consistent data."""
        records = [
            b'\x01\x02ABCD',
            b'\x01\x02ABEF',
            b'\x01\x02ABGH'
        ]
        anchors = find_stable_anchors(
            records, ns=[2], theta=0.6, eps_std=0.1, 
            max_start=10, merge_gap=0
        )
        # Should find anchor at position 2 (byte 0-1: \x01\x02)
        self.assertIn(2, anchors)
    
    def test_theta_filtering(self):
        """Test that theta filters out rare patterns."""
        records = [
            b'ABCD',
            b'ABEF',
            b'XYGH',
            b'XYIJ',
            b'XYKL'
        ]
        # With theta=0.6, need at least 3/5 = 60%
        anchors = find_stable_anchors(
            records, ns=[2], theta=0.6, eps_std=1.0,
            max_start=10, merge_gap=0
        )
        # 'XY' appears 3 times (60%), 'AB' only 2 times (40%)
        # Should find 'XY' but not 'AB'
        self.assertIn(2, anchors)  # XY anchor


class TestSegmentStats(unittest.TestCase):
    """Test segment statistics computation."""
    
    def test_compute_basic_stats(self):
        """Test computing basic segment statistics."""
        records = [
            b'AABBCCDD',
            b'AABBCCEE',
            b'AABBCCFF'
        ]
        boundaries = [2, 4, 6]
        stats = compute_segment_stats(records, boundaries)
        
        # Should have 3 segments
        self.assertEqual(len(stats), 3)
        
        # First segment (0-2) should be present in all records
        self.assertEqual(stats[0]['presence'], 1.0)
        self.assertEqual(stats[0]['len_mean'], 2.0)
    
    def test_partial_presence(self):
        """Test segments with partial presence."""
        records = [
            b'AABB',
            b'AABBCCDD',
            b'AABBCCDD'
        ]
        boundaries = [2, 4, 8]
        stats = compute_segment_stats(records, boundaries)
        
        # Third segment (4-8) should only be in 2/3 records
        self.assertAlmostEqual(stats[2]['presence'], 0.667, places=2)


class TestIntegration(unittest.TestCase):
    """Integration tests for full workflow."""
    
    def test_full_inference_pipeline(self):
        """Test complete inference from records to schema."""
        # Create synthetic records with consistent structure
        records = []
        for i in range(10):
            # Header: \x01\x02, Length: varies, Data: varies
            record = b'\x01\x02' + bytes([10 + i]) + b'DATA' + bytes([i] * 5)
            records.append(record)
        
        # Infer boundaries
        boundaries = find_stable_anchors(
            records, ns=[1, 2], theta=0.6, eps_std=1.5,
            max_start=64, merge_gap=0
        )
        
        # Should find at least the header boundary
        self.assertGreater(len(boundaries), 0)
        
        # Compute stats
        if boundaries:
            stats = compute_segment_stats(records, boundaries)
            self.assertGreater(len(stats), 0)


if __name__ == '__main__':
    unittest.main()
