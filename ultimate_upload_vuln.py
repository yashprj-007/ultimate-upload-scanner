#!/usr/bin/env python3
"""
Ultimate File Upload Vulnerability Detection Tool
- Polyglot payloads (JPEG/PNG/PDF/PHAR + PHP)
- Multi-threaded scanning
- Automatic path discovery & CSRF handling
- Interactive hex editor for manual payload crafting
- PUT method support
- Obfuscation techniques
- JSON config support with per-payload overrides
- Extended WAF bypass extension list
"""

import argparse
import concurrent.futures
import json
import os
import random
import re
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

# ===============================
# Constants
# ===============================
DEFAULT_EXTENSIONS = [
    "php", "php2", "php3", "php4", "php5", "php6", "php7", "php8", "phtml", "phps", "phar", "inc",
    "php.jpg", "php.png", "php.gif", "php;.jpg", "php%00.jpg", "php..jpg", "php.", "pHp", "PhP",
    "asp", "aspx", "jsp", "jspx", "cfm", "pl", "py", "rb"
]
POLYGLOT_TEMPLATES = {
    "jpeg": b"\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01<?php /*",
    "png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR<?php /*",
    "pdf": b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>\n<?php /*",
    "phar": b"<?php __HALT_COMPILER(); ?>\n\x00" + b"A"*100
}
POLYGLOT_FOOTERS = {
    "jpeg": b"\xFF\xD9<?php /*",
    "png": b"\x00\x00\x00\x00IEND\xAE\x42\x60\x82<?php /*"
}

# ===============================
# Helper functions
# ===============================
def hex_to_bytes(h: str) -> bytes:
    h = re.sub(r'\s', '', h)
    if len(h) % 2:
        raise ValueError(f"Odd hex length: {h}")
    return bytes.fromhex(h)

def interactive_hex_edit(original: bytes, desc: str) -> bytes:
    print(Fore.CYAN + f"\n--- Interactive Hex Editor for: {desc} ---")
    print(Fore.YELLOW + f"Current size: {len(original)} bytes")
    print(Fore.YELLOW + "Commands: v (view hex), e (edit hex), r (replace), a (append), p (prepend), s (save), q (quit)")
    data = bytearray(original)
    while True:
        cmd = input(Fore.GREEN + "hex> ").strip().lower()
        if cmd == 'v':
            view_len = min(256, len(data))
            hex_str = ' '.join(f"{b:02x}" for b in data[:view_len])
            print(Fore.WHITE + hex_str)
            if len(data) > view_len:
                print(Fore.WHITE + f"... and {len(data)-view_len} more bytes")
        elif cmd == 'e':
            offset = int(input("Offset (decimal or 0x): "), 0)
            hex_str = input("New hex: ")
            new_bytes = hex_to_bytes(hex_str)
            if offset + len(new_bytes) > len(data):
                data.extend(b'\x00' * (offset + len(new_bytes) - len(data)))
            data[offset:offset+len(new_bytes)] = new_bytes
            print(Fore.GREEN + f"Patched {len(new_bytes)} bytes at offset {offset}")
        elif cmd == 'r':
            search = hex_to_bytes(input("Search hex: "))
            replace = hex_to_bytes(input("Replace hex: "))
            data = bytearray(data.replace(search, replace))
            print(Fore.GREEN + "Replacement done")
        elif cmd == 'a':
            data.extend(hex_to_bytes(input("Append hex: ")))
        elif cmd == 'p':
            data = hex_to_bytes(input("Prepend hex: ")) + data
        elif cmd == 's':
            print(Fore.GREEN + "Saving changes")
            return bytes(data)
        elif cmd == 'q':
            print(Fore.YELLOW + "Discarding changes")
            return original
        else:
            print(Fore.RED + "Unknown command")

def generate_polyglot(payload: bytes, poly_type: str) -> bytes:
    if poly_type not in POLYGLOT_TEMPLATES:
        return payload
    template = POLYGLOT_TEMPLATES[poly_type]
    if poly_type == "phar":
        return template + b"\n" + payload
    else:
        return template + payload + POLYGLOT_FOOTERS.get(poly_type, b"")

def obfuscate_filename(original: str) -> str:
    name, ext = os.path.splitext(original)
    ext = ext.lstrip('.')
    techniques = [
        lambda: f"{name}.{ext}.jpg",
        lambda: f"{name}.{ext}%00.jpg",
        lambda: f"{name}.{ext};.jpg",
        lambda: f"{name}..{ext}",
        lambda: f"{name}.{ext} ",
        lambda: f"{name}.{ext}\n",
        lambda: f"{name}.{ext}".swapcase(),
        lambda: f"{name}.{ext}".replace('p', 'P').replace('h', 'H'),
    ]
    return random.choice(techniques)()

def extract_upload_path(resp_text: str, base_url: str) -> Optional[str]:
    patterns = [
        r'(/uploads?/[^\s"\'<>]+\.\w+)',
        r'(/files?/[^\s"\'<>]+\.\w+)',
        r'(/images?/[^\s"\'<>]+\.\w+)',
        r'"(/[^"]+\.\w+)"',
        r"'([^']+\.\w+)'"
    ]
    for pat in patterns:
        m = re.search(pat, resp_text, re.IGNORECASE)
        if m:
            path = m.group(1)
            if not path.startswith('http'):
                path = urljoin(base_url, path)
            return path
    return None

def get_csrf_token(url: str, session: requests.Session, csrf_patterns: List[str]) -> Optional[str]:
    try:
        resp = session.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        for pat in csrf_patterns:
            token = None
            if pat.startswith('name='):
                name = pat[5:]
                inp = soup.find('input', {'name': name})
                if inp and inp.get('value'):
                    token = inp['value']
            else:
                m = re.search(pat, resp.text, re.IGNORECASE)
                if m:
                    token = m.group(1)
            if token:
                return token
    except:
        pass
    return None

def test_upload(
    url: str,
    field_name: str,
    filename: str,
    content: bytes,
    method: str = "POST",
    headers: dict = None,
    cookies: dict = None,
    proxies: dict = None,
    timeout: int = 10,
    follow_redirects: bool = False,
    csrf_token: Optional[str] = None,
    csrf_param: Optional[str] = None,
) -> Tuple[int, str, Optional[str]]:
    if headers is None:
        headers = {}
    headers.setdefault('User-Agent', 'UltimateUploadScanner/3.0')
    session = requests.Session()
    session.cookies.update(cookies or {})
    session.proxies.update(proxies or {})
    
    data = {}
    files = None
    if method.upper() == "POST":
        if csrf_token and csrf_param:
            data[csrf_param] = csrf_token
        files = {field_name: (filename, content)}
        resp = session.post(url, files=files, data=data, headers=headers,
                            timeout=timeout, allow_redirects=follow_redirects)
    elif method.upper() == "PUT":
        resp = session.put(url + "/" + filename, data=content, headers=headers,
                           timeout=timeout, allow_redirects=follow_redirects)
    else:
        raise ValueError(f"Unsupported method: {method}")
    
    location = resp.headers.get('Location')
    return resp.status_code, resp.text, location

# ===============================
# Main scanner class
# ===============================
class UltimateUploadScanner:
    def __init__(self, args):
        self.args = args
        self.session = requests.Session()
        if args.proxy:
            self.session.proxies = {'http': args.proxy, 'https': args.proxy}
        self.results = []
        self.start_time = datetime.now()
        self.csrf_token = None
        if args.csrf_url:
            self.csrf_token = get_csrf_token(args.csrf_url, self.session, args.csrf_patterns or ['name=csrf_token'])
            if self.csrf_token:
                print(Fore.GREEN + f"[*] CSRF token obtained: {self.csrf_token[:20]}...")
        
        # Load config if provided
        self.config_payloads = []
        if args.config:
            self.load_config(args.config)
    
    def load_config(self, config_file: str):
        """Load JSON config and merge with command-line arguments."""
        with open(config_file, 'r') as f:
            cfg = json.load(f)
        
        # Extensions
        if 'extensions' in cfg:
            self.args.extensions = list(set((self.args.extensions or []) + cfg['extensions']))
        
        # Obfuscate flag
        if cfg.get('obfuscate_filenames'):
            self.args.obfuscate = True
        
        # Polyglot
        if 'polyglot' in cfg:
            self.args.polyglot = cfg['polyglot']
        
        # CSRF
        if 'csrf' in cfg:
            self.args.csrf_url = cfg['csrf'].get('url')
            self.args.csrf_param = cfg['csrf'].get('param', 'csrf_token')
            self.args.csrf_patterns = cfg['csrf'].get('patterns')
            if self.args.csrf_url:
                self.csrf_token = get_csrf_token(self.args.csrf_url, self.session, self.args.csrf_patterns or ['name=csrf_token'])
        
        # Access check
        if 'access_check' in cfg:
            self.args.access_url = cfg['access_check'].get('url_pattern')
        
        # Headers & Cookies
        if 'headers' in cfg:
            self.args.headers_dict.update(cfg['headers'])
        if 'cookies' in cfg:
            self.args.cookies_dict.update(cfg['cookies'])
        
        # Proxy
        if 'proxy' in cfg:
            self.args.proxy = cfg['proxy']
            self.session.proxies = {'http': cfg['proxy'], 'https': cfg['proxy']}
        
        # Threads, timeout
        if 'threads' in cfg:
            self.args.threads = cfg['threads']
        if 'timeout' in cfg:
            self.args.timeout = cfg['timeout']
        
        # Payloads from config
        if 'payloads' in cfg:
            self.config_payloads = cfg['payloads']
    
    def apply_hex_mods(self, data: bytes, mods: dict = None) -> bytes:
        """Apply hex modifications from command line or config dict."""
        if mods is None:
            # Command-line mods
            if self.args.replace_hex:
                for search, replace in self.args.replace_hex:
                    data = data.replace(hex_to_bytes(search), hex_to_bytes(replace))
            if self.args.patch_hex:
                for offset_str, hex_str in self.args.patch_hex:
                    offset = int(offset_str, 0)
                    patch = hex_to_bytes(hex_str)
                    if offset + len(patch) > len(data):
                        data += b'\x00' * (offset + len(patch) - len(data))
                    data = data[:offset] + patch + data[offset+len(patch):]
            if self.args.append_hex:
                data += hex_to_bytes(self.args.append_hex)
            if self.args.prepend_hex:
                data = hex_to_bytes(self.args.prepend_hex) + data
        else:
            # Config mods
            if 'replace' in mods:
                for search, replace in mods['replace']:
                    data = data.replace(hex_to_bytes(search), hex_to_bytes(replace))
            if 'patch' in mods:
                for offset_str, hex_str in mods['patch']:
                    offset = int(offset_str, 0)
                    patch = hex_to_bytes(hex_str)
                    if offset + len(patch) > len(data):
                        data += b'\x00' * (offset + len(patch) - len(data))
                    data = data[:offset] + patch + data[offset+len(patch):]
            if 'append' in mods:
                data += hex_to_bytes(mods['append'])
            if 'prepend' in mods:
                data = hex_to_bytes(mods['prepend']) + data
        return data
    
    def load_payloads(self) -> List[Tuple[str, bytes, dict]]:
        """Return list of (description, content, overrides_dict)."""
        payloads = []
        
        # Command-line manual files
        if self.args.manual_files:
            for path in self.args.manual_files:
                if os.path.isfile(path):
                    with open(path, 'rb') as f:
                        orig = f.read()
                    if self.args.interactive_hex:
                        data = interactive_hex_edit(orig, path)
                    else:
                        data = self.apply_hex_mods(orig)
                    payloads.append((f"File: {path}", data, {}))
                else:
                    print(Fore.RED + f"File not found: {path}")
        
        # Config payloads
        for p in self.config_payloads:
            overrides = {}
            if 'file' in p:
                path = p['file']
                if os.path.isfile(path):
                    with open(path, 'rb') as f:
                        orig = f.read()
                    if 'hex_mods' in p:
                        data = self.apply_hex_mods(orig, p['hex_mods'])
                    else:
                        data = orig
                    desc = p.get('description', f"Config file: {path}")
                    overrides = {
                        'obfuscate': p.get('obfuscate_filename', False),
                        'polyglot': p.get('polyglot'),
                        'mime_spoof': p.get('mime_spoof'),
                        'extensions_override': p.get('extensions_override')
                    }
                    payloads.append((desc, data, overrides))
            elif 'hex' in p:
                hex_str = p['hex']
                try:
                    data = hex_to_bytes(hex_str)
                    desc = p.get('description', "Config hex payload")
                    overrides = {
                        'obfuscate': p.get('obfuscate_filename', False),
                        'polyglot': p.get('polyglot'),
                        'mime_spoof': p.get('mime_spoof'),
                        'extensions_override': p.get('extensions_override')
                    }
                    payloads.append((desc, data, overrides))
                except ValueError as e:
                    print(Fore.RED + f"Invalid hex in config: {e}")
        
        # Polyglot from command line (if no config payloads)
        if self.args.polyglot and not self.config_payloads and not self.args.manual_files:
            for poly in self.args.polyglot:
                php_payload = b"<?php echo 'VULN_' . md5('test'); ?>"
                poly_data = generate_polyglot(php_payload, poly)
                payloads.append((f"Polyglot: {poly}", poly_data, {}))
        
        # Default
        if not payloads:
            payloads.append(("Default PHP", b"<?php echo 'VULN_TEST'; ?>", {}))
        
        return payloads
    
    def run(self):
        # Build extension list
        extensions = self.args.extensions or DEFAULT_EXTENSIONS
        if self.args.wordlist:
            with open(self.args.wordlist, 'r') as f:
                extensions += [line.strip() for line in f if line.strip()]
        extensions = list(set(extensions))
        
        payloads = self.load_payloads()
        
        # Prepare tasks: each task is (ext, payload_desc, content, overrides, original_ext_for_obfuscation)
        tasks = []
        for ext in extensions:
            for desc, content, overrides in payloads:
                # Determine filename
                if overrides.get('obfuscate') or self.args.obfuscate:
                    obf_name = obfuscate_filename(f"test.{ext}")
                else:
                    obf_name = f"test.{ext}"
                # Apply polyglot if overridden
                final_content = content
                if overrides.get('polyglot'):
                    final_content = generate_polyglot(content, overrides['polyglot'])
                tasks.append((ext, desc, final_content, obf_name, overrides))
        
        total_tests = len(tasks)
        print(Fore.CYAN + f"[*] Total tests: {total_tests}")
        print(Fore.CYAN + f"[*] Threads: {self.args.threads}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            future_to_task = {executor.submit(self.single_test, task): task for task in tasks}
            for future in concurrent.futures.as_completed(future_to_task):
                task = future_to_task[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    self.print_result(result)
                except Exception as e:
                    print(Fore.RED + f"Error testing {task[3]}: {e}")
        
        self.generate_report()
    
    def single_test(self, task):
        ext, payload_desc, content, filename, overrides = task
        test_name = f"{filename} ({payload_desc})"
        
        # Use custom Content-Type if provided
        content_type = overrides.get('mime_spoof')
        
        # Use overridden extensions if present
        if overrides.get('extensions_override'):
            # This test uses a different set, but we already loop over extensions.
            # We'll just use the filename as is; the extension is already in the loop.
            pass
        
        status, resp_text, location = test_upload(
            url=self.args.url,
            field_name=self.args.field_name,
            filename=filename,
            content=content,
            method=self.args.method,
            headers=self.args.headers_dict,
            cookies=self.args.cookies_dict,
            proxies=self.args.proxy_dict,
            timeout=self.args.timeout,
            follow_redirects=self.args.follow_redirects,
            csrf_token=self.csrf_token,
            csrf_param=self.args.csrf_param
        )
        
        accessed = False
        access_url = None
        if self.args.access_url:
            check_url = self.args.access_url.replace('{filename}', filename)
            try:
                check_resp = self.session.get(check_url, timeout=self.args.timeout)
                if content in check_resp.content:
                    accessed = True
            except:
                pass
        elif status == 200 and not self.args.access_url:
            detected = extract_upload_path(resp_text, self.args.url)
            if detected:
                access_url = detected
                try:
                    check_resp = self.session.get(detected, timeout=self.args.timeout)
                    if content in check_resp.content:
                        accessed = True
                except:
                    pass
        
        return {
            "test_name": test_name,
            "filename": filename,
            "status_code": status,
            "response_preview": resp_text[:200],
            "location": location,
            "accessed": accessed,
            "access_url": access_url,
            "payload_desc": payload_desc
        }
    
    def print_result(self, res):
        status = res['status_code']
        test_name = res['test_name']
        if status == 0:
            print(Fore.RED + f"[!] {test_name} - CONNECTION ERROR")
            return
        if 200 <= status < 300:
            if res['accessed']:
                print(Fore.RED + Style.BRIGHT + f"[🔥] {test_name} - VULNERABLE! HTTP {status} - Executed")
            else:
                print(Fore.YELLOW + f"[⚠️] {test_name} - HTTP {status} (upload may have succeeded)")
        else:
            print(Fore.WHITE + f"[-] {test_name} - HTTP {status}")
    
    def generate_report(self):
        report_file = self.args.report or f"upload_scan_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json"
        vulnerable = [r for r in self.results if r['accessed']]
        summary = {
            "scan_start": self.start_time.isoformat(),
            "scan_end": datetime.now().isoformat(),
            "target": self.args.url,
            "total_tests": len(self.results),
            "vulnerable_found": len(vulnerable),
            "vulnerable_tests": vulnerable
        }
        with open(report_file, 'w') as f:
            json.dump(summary, f, indent=2)
        print(Fore.GREEN + f"\n[+] Report saved to {report_file}")
        if vulnerable:
            print(Fore.RED + f"\n[!] Found {len(vulnerable)} vulnerable upload(s)!")
            for v in vulnerable:
                print(Fore.RED + f"    - {v['test_name']} -> {v.get('access_url', 'unknown')}")
        else:
            print(Fore.YELLOW + "\n[-] No clear vulnerability detected. Consider manual review.")

# ===============================
# Argument parsing
# ===============================
def parse_args():
    parser = argparse.ArgumentParser(description="Ultimate File Upload Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target upload endpoint")
    parser.add_argument("--config", help="JSON configuration file")
    parser.add_argument("--field-name", default="file", help="Multipart field name")
    parser.add_argument("--method", default="POST", choices=["POST", "PUT"], help="HTTP method")
    parser.add_argument("--extensions", nargs="+", help="Extensions to test (default: many variants)")
    parser.add_argument("--wordlist", help="File with extra extensions (one per line)")
    parser.add_argument("--manual-files", nargs="+", help="Paths to files to upload")
    parser.add_argument("--polyglot", nargs="+", choices=["jpeg","png","pdf","phar"], help="Generate polyglot payloads")
    parser.add_argument("--obfuscate", action="store_true", help="Enable filename obfuscation")
    parser.add_argument("--interactive-hex", action="store_true", help="Manually edit each file's hex before upload")
    parser.add_argument("--replace-hex", nargs=2, action='append', metavar=('SEARCH','REPLACE'))
    parser.add_argument("--patch-hex", nargs=2, action='append', metavar=('OFFSET','HEX'))
    parser.add_argument("--append-hex", help="Hex to append")
    parser.add_argument("--prepend-hex", help="Hex to prepend")
    parser.add_argument("--access-url", help="URL pattern to check uploaded file, use {filename}")
    parser.add_argument("--csrf-url", help="URL to fetch CSRF token from")
    parser.add_argument("--csrf-param", default="csrf_token", help="Parameter name for CSRF token")
    parser.add_argument("--csrf-patterns", nargs="+", help="Regex or name=... patterns to extract token")
    parser.add_argument("--headers", nargs="+", help="Custom headers: 'Name: Value'")
    parser.add_argument("--cookies", nargs="+", help="Cookies: 'name=value'")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--follow-redirects", action="store_true")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("--report", help="Output JSON report file")
    args = parser.parse_args()
    
    args.headers_dict = {}
    if args.headers:
        for h in args.headers:
            if ':' in h:
                k, v = h.split(':', 1)
                args.headers_dict[k.strip()] = v.strip()
    args.cookies_dict = {}
    if args.cookies:
        for c in args.cookies:
            if '=' in c:
                k, v = c.split('=', 1)
                args.cookies_dict[k.strip()] = v.strip()
    args.proxy_dict = {'http': args.proxy, 'https': args.proxy} if args.proxy else {}
    return args

if __name__ == "__main__":
    args = parse_args()
    scanner = UltimateUploadScanner(args)
    scanner.run()
