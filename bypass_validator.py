#!/usr/bin/env python3
"""
Real-Time Bypass Validator
Re-tests all bypasses from JSON to verify they still work

Usage: python bypass_validator.py bypasses.json
"""

import json
import sys
import requests
import time
import urllib.parse
from urllib.parse import urlparse
import gzip
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import ssl

class BypassValidator:
    def __init__(self, json_file):
        self.json_file = json_file
        self.data = self.load_json()
        self.target_url = self.data['target_url']
        self.session = self.create_session()
        self.results = {
            'target': self.target_url,
            'test_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_bypasses': 0,
            'working_bypasses': 0,
            'broken_bypasses': 0,
            'untestable_bypasses': 0,
            'bypass_results': []
        }
        
    def load_json(self):
        """Load bypass data from JSON file"""
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Error loading JSON: {e}")
            sys.exit(1)
    
    def create_session(self):
        """Create requests session with proper configuration"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Configure retries
        from requests.adapters import HTTPAdapter
        from requests.packages.urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def test_baseline(self, original_path="/admin"):
        """Test baseline request to compare against"""
        try:
            print(f"🔍 Testing baseline: {original_path}")
            
            response = self.session.get(
                f"{self.target_url}{original_path}",
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            
            result = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'location': response.headers.get('Location', ''),
                'server': response.headers.get('Server', ''),
                'response_time': response.elapsed.total_seconds()
            }
            
            print(f"  └─ Baseline: {response.status_code} ({len(response.content)} bytes)")
            return result
            
        except Exception as e:
            print(f"  └─ Baseline error: {e}")
            return None
    
    def test_bypass_request(self, bypass_data):
        """Test a specific bypass"""
        bypass_id = bypass_data['id']
        bypass_type = bypass_data['type']
        
        print(f"\n🧪 Testing {bypass_id}: {bypass_type}")
        
        result = {
            'bypass_id': bypass_id,
            'bypass_type': bypass_type,
            'description': bypass_data.get('description', ''),
            'original_validated': bypass_data.get('validated', False),
            'currently_working': False,
            'testable': True,
            'error': None,
            'original_payload': bypass_data.get('payload', ''),
            'test_results': {}
        }
        
        # Handle different bypass types
        if bypass_type == "Unicode Bypass":
            result = self.test_unicode_bypass(bypass_data, result)
        elif bypass_type == "Encoding Bypass":
            result = self.test_encoding_bypass(bypass_data, result)
        elif bypass_type == "Path Bypass":
            result = self.test_path_bypass(bypass_data, result)
        elif bypass_type == "TCP Fragmentation Bypass":
            result = self.test_tcp_fragmentation_bypass(bypass_data, result)
        elif bypass_type == "Compression Bomb Bypass":
            result = self.test_compression_bypass(bypass_data, result)
        elif bypass_type == "Buffer Overflow Bypass":
            result = self.test_buffer_bypass(bypass_data, result)
        else:
            result['testable'] = False
            result['error'] = f"Unknown bypass type: {bypass_type}"
            print(f"  └─ ❓ Unknown bypass type: {bypass_type}")
        
        return result
    
    def test_unicode_bypass(self, bypass_data, result):
        """Test Unicode-based bypass"""
        try:
            curl_data = bypass_data.get('curl_data', {})
            path = curl_data.get('path', bypass_data.get('payload', ''))
            
            # Test the bypass
            response = self.session.get(
                f"{self.target_url}{path}",
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            
            result['test_results'] = {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'headers': dict(response.headers),
                'location': response.headers.get('Location', ''),
                'response_time': response.elapsed.total_seconds()
            }
            
            # Check if bypass is working (not 403/404)
            if response.status_code not in [403, 404]:
                result['currently_working'] = True
                print(f"  └─ ✅ WORKING: {response.status_code} ({len(response.content)} bytes)")
            else:
                print(f"  └─ ❌ BLOCKED: {response.status_code}")
            
        except Exception as e:
            result['error'] = str(e)
            print(f"  └─ ❌ ERROR: {e}")
        
        return result
    
    def test_encoding_bypass(self, bypass_data, result):
        """Test encoding-based bypass"""
        try:
            curl_data = bypass_data.get('curl_data', {})
            path = curl_data.get('path', bypass_data.get('payload', ''))
            
            # Test the bypass
            response = self.session.get(
                f"{self.target_url}{path}",
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            
            result['test_results'] = {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'headers': dict(response.headers),
                'location': response.headers.get('Location', ''),
                'response_time': response.elapsed.total_seconds()
            }
            
            # Check if bypass is working
            if response.status_code not in [403, 404]:
                result['currently_working'] = True
                print(f"  └─ ✅ WORKING: {response.status_code} ({len(response.content)} bytes)")
            else:
                print(f"  └─ ❌ BLOCKED: {response.status_code}")
            
        except Exception as e:
            result['error'] = str(e)
            print(f"  └─ ❌ ERROR: {e}")
        
        return result
    
    def test_path_bypass(self, bypass_data, result):
        """Test path-based bypass"""
        try:
            curl_data = bypass_data.get('curl_data', {})
            path = curl_data.get('path', bypass_data.get('payload', ''))
            
            # Test the bypass
            response = self.session.get(
                f"{self.target_url}{path}",
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            
            result['test_results'] = {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'headers': dict(response.headers),
                'location': response.headers.get('Location', ''),
                'response_time': response.elapsed.total_seconds()
            }
            
            # Check if bypass is working
            if response.status_code not in [403, 404]:
                result['currently_working'] = True
                print(f"  └─ ✅ WORKING: {response.status_code} ({len(response.content)} bytes)")
            else:
                print(f"  └─ ❌ BLOCKED: {response.status_code}")
            
        except Exception as e:
            result['error'] = str(e)
            print(f"  └─ ❌ ERROR: {e}")
        
        return result
    
    def test_tcp_fragmentation_bypass(self, bypass_data, result):
        """Test TCP fragmentation bypass"""
        try:
            # This requires raw socket programming - mark as untestable for now
            result['testable'] = False
            result['error'] = "TCP Fragmentation requires raw socket programming - not testable via HTTP"
            print(f"  └─ ⚠️ UNTESTABLE: Requires raw socket programming")
            
        except Exception as e:
            result['error'] = str(e)
            print(f"  └─ ❌ ERROR: {e}")
        
        return result
    
    def test_compression_bypass(self, bypass_data, result):
        """Test compression bypass"""
        try:
            # Create compressed payload
            large_payload = "A" * 10000
            compressed_payload = gzip.compress(large_payload.encode())
            
            headers = {
                'Content-Encoding': 'gzip',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': str(len(compressed_payload))
            }
            
            response = self.session.post(
                self.target_url,
                data=compressed_payload,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            
            result['test_results'] = {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'headers': dict(response.headers),
                'compressed_size': len(compressed_payload),
                'uncompressed_size': len(large_payload),
                'compression_ratio': len(large_payload) / len(compressed_payload),
                'response_time': response.elapsed.total_seconds()
            }
            
            # Check if compression bypass works (server processes it)
            if response.status_code in [200, 413, 414, 502]:
                result['currently_working'] = True
                print(f"  └─ ✅ WORKING: {response.status_code} (ratio: {result['test_results']['compression_ratio']:.1f}x)")
            else:
                print(f"  └─ ❌ BLOCKED: {response.status_code}")
            
        except Exception as e:
            result['error'] = str(e)
            print(f"  └─ ❌ ERROR: {e}")
        
        return result
    
    def test_buffer_bypass(self, bypass_data, result):
        """Test buffer overflow bypass"""
        try:
            curl_data = bypass_data.get('curl_data', {})
            headers = curl_data.get('headers', {})
            
            # Test the bypass
            response = self.session.get(
                self.target_url,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            
            result['test_results'] = {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'headers': dict(response.headers),
                'large_header_size': len(headers.get('X-Large-Header', '')),
                'response_time': response.elapsed.total_seconds()
            }
            
            # Check if buffer bypass works
            if response.status_code not in [403, 404, 413, 414]:
                result['currently_working'] = True
                print(f"  └─ ✅ WORKING: {response.status_code} (header: {result['test_results']['large_header_size']} bytes)")
            else:
                print(f"  └─ ❌ BLOCKED: {response.status_code}")
            
        except Exception as e:
            result['error'] = str(e)
            print(f"  └─ ❌ ERROR: {e}")
        
        return result
    
    def run_validation(self):
        """Run validation on all bypasses"""
        print(f"🎯 Target: {self.target_url}")
        print(f"📊 Total bypasses in JSON: {len(self.data['bypasses'])}")
        
        # Get only validated bypasses
        validated_bypasses = [b for b in self.data['bypasses'] if b.get('validated', False)]
        print(f"✅ Originally validated: {len(validated_bypasses)}")
        
        # Test baseline first
        baseline = self.test_baseline()
        
        # Test each bypass
        print(f"\n{'='*60}")
        print("🧪 TESTING BYPASSES")
        print('='*60)
        
        for bypass_data in validated_bypasses:
            result = self.test_bypass_request(bypass_data)
            self.results['bypass_results'].append(result)
            
            if result['testable']:
                self.results['total_bypasses'] += 1
                if result['currently_working']:
                    self.results['working_bypasses'] += 1
                else:
                    self.results['broken_bypasses'] += 1
            else:
                self.results['untestable_bypasses'] += 1
            
            # Small delay between tests
            time.sleep(0.5)
    
    def print_summary(self):
        """Print test summary"""
        print(f"\n{'='*60}")
        print("📋 VALIDATION SUMMARY")
        print('='*60)
        
        print(f"🎯 Target: {self.target_url}")
        print(f"⏰ Test Time: {self.results['test_timestamp']}")
        print(f"📊 Total Testable: {self.results['total_bypasses']}")
        print(f"✅ Currently Working: {self.results['working_bypasses']}")
        print(f"❌ Broken: {self.results['broken_bypasses']}")
        print(f"⚠️ Untestable: {self.results['untestable_bypasses']}")
        
        if self.results['working_bypasses'] > 0:
            print(f"\n🎉 WORKING BYPASSES:")
            for result in self.results['bypass_results']:
                if result['currently_working']:
                    print(f"  ✅ {result['bypass_id']}: {result['bypass_type']}")
                    if 'test_results' in result:
                        status = result['test_results'].get('status_code', 'N/A')
                        print(f"     └─ Status: {status}")
        
        if self.results['broken_bypasses'] > 0:
            print(f"\n💔 BROKEN BYPASSES:")
            for result in self.results['bypass_results']:
                if result['testable'] and not result['currently_working']:
                    print(f"  ❌ {result['bypass_id']}: {result['bypass_type']}")
                    if 'test_results' in result:
                        status = result['test_results'].get('status_code', 'N/A')
                        print(f"     └─ Status: {status}")
        
        if self.results['untestable_bypasses'] > 0:
            print(f"\n⚠️ UNTESTABLE BYPASSES:")
            for result in self.results['bypass_results']:
                if not result['testable']:
                    print(f"  ⚠️ {result['bypass_id']}: {result['bypass_type']}")
                    print(f"     └─ Reason: {result['error']}")
        
        print(f"\n{'='*60}")
        
        # Success rate
        if self.results['total_bypasses'] > 0:
            success_rate = (self.results['working_bypasses'] / self.results['total_bypasses']) * 100
            print(f"📈 Success Rate: {success_rate:.1f}% ({self.results['working_bypasses']}/{self.results['total_bypasses']})")
        
    def export_results(self, filename=None):
        """Export validation results to JSON"""
        if not filename:
            timestamp = int(time.time())
            parsed_url = urlparse(self.target_url)
            filename = f"bypass_validation_{parsed_url.netloc}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"💾 Results exported to: {filename}")
        return filename


def main():
    if len(sys.argv) != 2:
        print("Usage: python bypass_validator.py <bypasses.json>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    
    print("🔍 REAL-TIME BYPASS VALIDATOR")
    print("=" * 50)
    
    # Initialize validator
    validator = BypassValidator(json_file)
    
    # Run validation
    validator.run_validation()
    
    # Print summary
    validator.print_summary()
    
    # Export results
    validator.export_results()


if __name__ == "__main__":
    main()