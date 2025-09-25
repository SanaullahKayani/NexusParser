"""
SCM Log Extractor: keep only ERROR/WARN/CRITICAL (incl. FATAL/SEVERE), exclude INFO/DEBUG.
Supports optional time and location filters; writes a normalized CSV.
"""

import json
import csv
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

class SCMLogExtractor:
    def __init__(self, scm_directory: str, output_csv: str):
        self.scm_directory = Path(scm_directory)
        self.output_csv = output_csv
        self.extracted_logs = []
        
        # Define log levels to extract (case-insensitive) - ONLY ERROR, WARN, CRITICAL levels
        # INFO and DEBUG are explicitly EXCLUDED
        self.target_levels = ['ERROR', 'WARN', 'WARNING', 'CRITICAL', 'FATAL', 'SEVERE']
        
        # Define log purposes to extract
        self.target_purposes = ['Audit', 'Technical', 'Statistics']
        
        # Track processing statistics
        self.stats = {
            'files_processed': 0,
            'total_logs_found': 0,
            'target_logs_extracted': 0,
            'time_filtered_out': 0,
            'info_logs_excluded': 0,
            'location_filtered_out': 0,
            'json_parse_errors': 0,
            'unparseable_lines': 0
        }

        # Optional time window filtering (inclusive) via environment variables
        # Use ISO-8601 strings, e.g., 2025-08-12T00:00:00 or 2025-08-12T00:00:00Z
        self.start_time_str = os.environ.get('EXTRACT_START', '').strip()
        self.end_time_str = os.environ.get('EXTRACT_END', '').strip()
        self.start_dt: Optional[datetime] = self._parse_iso_ts(self.start_time_str) if self.start_time_str else None
        self.end_dt: Optional[datetime] = self._parse_iso_ts(self.end_time_str) if self.end_time_str else None

        # Optional location filters via environment variables
        self.filter_city_raw = os.environ.get('EXTRACT_CITY', '').strip()
        self.filter_server_raw = os.environ.get('EXTRACT_SERVER', '').strip()
        self.filter_city = self._normalize_city(self.filter_city_raw) if self.filter_city_raw else None
        self.filter_server = self._normalize_server(self.filter_server_raw) if self.filter_server_raw else None

    def is_target_log_level(self, level: str) -> bool:
        """Check if log level matches our target levels"""
        if not level:
            return False
        level_upper = level.upper()
        
        # Explicitly exclude INFO and DEBUG
        if level_upper in ['INFO', 'DEBUG']:
            return False
            
        return level_upper in [l.upper() for l in self.target_levels]
    
    def should_exclude_log(self, log: Dict[str, Any]) -> bool:
        """Check if a log should be explicitly excluded"""
        log_level = log.get('log_level', '').upper()
        
        # Always exclude INFO and DEBUG
        if log_level in ['INFO', 'DEBUG']:
            self.stats['info_logs_excluded'] += 1
            return True
            
        return False

    def _normalize_city(self, value: str) -> Optional[str]:
        v = value.strip().lower()
        if not v:
            return None
        if v.startswith('lyon'):
            return 'lyon'
        if v.startswith('sing'):  # singapor/singapore
            return 'singapore'
        return v

    def _normalize_server(self, value: str) -> Optional[str]:
        v = value.strip().lower()
        if not v:
            return None
        # Accept forms like "1", "server1", "srv1"
        m = re.search(r'(?:server|srv)?\s*(\d)', v)
        if m:
            return m.group(1)
        return v

    def _extract_site_info(self, source_or_host: str) -> (Optional[str], Optional[str]):
        """Return (city, server) inferred from MSV code in path/hostname."""
        m = re.search(r'(?i)MSV(\d{3})', source_or_host)
        code = m.group(1) if m else None
        mapping = {
            '101': ('lyon', '1'),
            '102': ('lyon', '2'),
            '301': ('singapore', '1'),
            '302': ('singapore', '2'),
        }
        if code and code in mapping:
            return mapping[code]
        return (None, None)

    def _parse_iso_ts(self, value: str) -> Optional[datetime]:
        """Parse ISO-like timestamps; return None on failure."""
        v = value.strip()
        try:
            return datetime.fromisoformat(v.replace('Z', '+00:00'))
        except Exception:
            pass
        for fmt in (
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%d %H:%M:%S.%f',
        ):
            try:
                return datetime.strptime(v, fmt)
            except Exception:
                continue
        return None

    def _is_within_time_range(self, log: Dict[str, Any]) -> bool:
        """Check [start,end] window; missing/unparseable counts as out-of-range when set."""
        if self.start_dt is None and self.end_dt is None:
            return True
        ts_str = (log.get('log_timestamp') or '').strip()
        if not ts_str:
            return False
        ts = self._parse_iso_ts(ts_str)
        if ts is None:
            return False
        if self.start_dt is not None and ts < self.start_dt:
            return False
        if self.end_dt is not None and ts > self.end_dt:
            return False
        return True

    def _passes_location_filter(self, log: Dict[str, Any]) -> bool:
        """Filter by city/server when set; fail if cannot infer under filtering."""
        if self.filter_city is None and self.filter_server is None:
            return True
        src = (log.get('source_file') or '').strip()
        host = (log.get('log_hostname') or '').strip()
        city, server = (None, None)
        if src:
            city, server = self._extract_site_info(src)
        if city is None and host:
            city, server = self._extract_site_info(host)
        if self.filter_city is not None and (city is None or city != self.filter_city):
            return False
        if self.filter_server is not None and (server is None or server != self.filter_server):
            return False
        return True

    def parse_json_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single JSON log line"""
        try:
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                return json.loads(line)
            return None
        except json.JSONDecodeError:
            self.stats['json_parse_errors'] += 1
            return None

    def parse_multi_line_json(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse multi-line JSON where entries span multiple lines."""
        logs = []
        current_json_lines = []
        
        for line in lines:
            line = line.strip()
            if line.startswith('{'):
                # Start of new JSON
                if current_json_lines:
                    try:
                        combined = ''.join(current_json_lines)
                        logs.append(json.loads(combined))
                    except json.JSONDecodeError:
                        self.stats['json_parse_errors'] += 1
                current_json_lines = [line]
            elif line.endswith('}') and current_json_lines:
                # End of JSON
                current_json_lines.append(line)
                try:
                    combined = ''.join(current_json_lines)
                    logs.append(json.loads(combined))
                except json.JSONDecodeError:
                    self.stats['json_parse_errors'] += 1
                current_json_lines = []
            elif current_json_lines:
                # Middle of JSON
                current_json_lines.append(line)
        
        # Handle last entry
        if current_json_lines:
            try:
                combined = ''.join(current_json_lines)
                logs.append(json.loads(combined))
            except json.JSONDecodeError:
                self.stats['json_parse_errors'] += 1
        
        return logs

    def parse_traditional_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse traditional log formats (syslog, postfix, nginx, etc.)"""
        line = line.strip()
        if not line:
            return None
            
        # Try to extract log level from traditional formats
        log_entry = {
            'log_timestamp': '',
            'log_purpose': 'Traditional',
            'log_hostname': '',
            'log_application': '',
            'log_service': '',
            'log_instance': '',
            'log_level': '',
            'log_office': '',
            'log_country': '',
            'log_roles': '',
            'log_message': line,
            'log_info': [],
            'source_file': '',
            'file_type': 'traditional'
        }
        
        # Extract timestamp if present
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
        if timestamp_match:
            log_entry['log_timestamp'] = timestamp_match.group(1)
        
        # Extract log level from various traditional formats
        level_patterns = [
            r'\b(ERROR|WARN|WARNING|CRITICAL|FATAL|SEVERE|INFO|DEBUG)\b',
            r'\[(ERROR|WARN|WARNING|CRITICAL|FATAL|SEVERE|INFO|DEBUG)\]',
            r'level="(ERROR|WARN|WARNING|CRITICAL|FATAL|SEVERE|INFO|DEBUG)"'
        ]
        
        for pattern in level_patterns:
            level_match = re.search(pattern, line, re.IGNORECASE)
            if level_match:
                log_entry['log_level'] = level_match.group(1).upper()
                break
        
        # Extract hostname if present
        hostname_match = re.search(r'(\w+\.\w+\.\w+)', line)
        if hostname_match:
            log_entry['log_hostname'] = hostname_match.group(1)
        
        return log_entry

    def process_json_log_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Load a file and parse JSON logs (single- or multi-line)."""
        logs = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()
                
            # Try single-line JSON first
            for line in lines:
                log_entry = self.parse_json_log_line(line)
                if log_entry:
                    logs.append(log_entry)
                    self.stats['total_logs_found'] += 1
            
            # If no single-line JSON found, try multi-line
            if not logs:
                logs = self.parse_multi_line_json(lines)
                self.stats['total_logs_found'] += len(logs)
                
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            
        return logs

    def process_traditional_log_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Stream-parse plaintext logs line-by-line."""
        logs = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    log_entry = self.parse_traditional_log_line(line)
                    if log_entry:
                        logs.append(log_entry)
                        self.stats['total_logs_found'] += 1
                        
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            
        return logs

    def determine_file_type(self, file_path: Path) -> str:
        """Heuristically decide if file holds JSON or traditional logs."""
        filename = file_path.name.lower()
        
        # JSON-structured logs
        if any(keyword in filename for keyword in ['technical', 'audit', 'statistics']):
            return 'json'
        
        # Traditional logs
        if any(keyword in filename for keyword in ['postfix', 'nginx', 'access', 'error', 'journal', 'maillog', 'var.log']):
            return 'traditional'
        
        # Default to JSON for unknown types
        return 'json'

    def process_log_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Dispatch to the appropriate parser and tag entries with source/type."""
        file_type = self.determine_file_type(file_path)
        
        if file_type == 'json':
            logs = self.process_json_log_file(file_path)
        else:
            logs = self.process_traditional_log_file(file_path)
        
        # Add source file information
        for log in logs:
            log['source_file'] = str(file_path)
            log['file_type'] = file_type
        
        return logs

    def extract_target_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Keep only target levels after applying time/location filters."""
        target_logs = []
        
        for log in logs:
            # Apply optional time filter first
            if not self._is_within_time_range(log):
                self.stats['time_filtered_out'] += 1
                continue
            # Apply optional location filter (city/server)
            if not self._passes_location_filter(log):
                self.stats['location_filtered_out'] += 1
                continue
            # First check: explicitly exclude INFO and DEBUG logs
            if self.should_exclude_log(log):
                continue
                
            log_level = log.get('log_level', '').upper()
            
            # Only include logs with target log levels (ERROR, WARN, CRITICAL, etc.)
            if self.is_target_log_level(log_level):
                target_logs.append(log)
                self.stats['target_logs_extracted'] += 1
                continue
            
            # For audit logs: ONLY include if they have ERROR/WARN/CRITICAL level
            if log.get('log_purpose') == 'Audit':
                if log_level in ['ERROR', 'WARN', 'WARNING', 'CRITICAL', 'FATAL', 'SEVERE']:
                    target_logs.append(log)
                    self.stats['target_logs_extracted'] += 1
                    continue
        
        return target_logs

    def process_directory(self):
        """Walk the SCM directory tree and aggregate parsed logs."""
        print(f"Starting to process SCM directory: {self.scm_directory}")
        print("=" * 60)
        
        # Walk through all subdirectories
        for root, dirs, files in os.walk(self.scm_directory):
            root_path = Path(root)
            
            # Process log files
            for file in files:
                if file.endswith('.log') or file.endswith('.txt'):
                    file_path = root_path / file
                    
                    try:
                        # Skip empty files
                        if file_path.stat().st_size == 0:
                            continue
                            
                        print(f"Processing: {file_path}")
                        
                        # Process the log file
                        logs = self.process_log_file(file_path)
                        
                        # Extract target logs
                        target_logs = self.extract_target_logs(logs)
                        
                        # Add to our collection
                        self.extracted_logs.extend(target_logs)
                        
                        self.stats['files_processed'] += 1
                        
                        if target_logs:
                            print(f"  ✓ Found {len(target_logs)} target logs")
                        else:
                            print(f"  - No target logs found")
                            
                    except Exception as e:
                        print(f"  ✗ Error processing {file_path}: {e}")
                        continue
        
        print("=" * 60)
        print("Processing complete!")

    def export_to_csv(self):
        """Write normalized rows to CSV; flattens log_info."""
        if not self.extracted_logs:
            print("No logs to export!")
            return
        
        # Define CSV fields
        fieldnames = [
            'Timestamp', 'LogLevel', 'LogPurpose', 'Hostname', 'Application', 
            'Service', 'Instance', 'Office', 'Country', 'Roles', 'Message', 
            'SourceFile', 'FileType', 'LogInfo'
        ]
        
        try:
            with open(self.output_csv, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for log in self.extracted_logs:
                    # Prepare log_info as string
                    log_info = log.get('log_info', [])
                    if isinstance(log_info, list):
                        log_info_str = '; '.join([f"{item.get('name', '')}:{item.get('value', '')}" for item in log_info])
                    else:
                        log_info_str = str(log_info)
                    
                    row = {
                        'Timestamp': log.get('log_timestamp', ''),
                        'LogLevel': log.get('log_level', ''),
                        'LogPurpose': log.get('log_purpose', ''),
                        'Hostname': log.get('log_hostname', ''),
                        'Application': log.get('log_application', ''),
                        'Service': log.get('log_service', ''),
                        'Instance': log.get('log_instance', ''),
                        'Office': log.get('log_office', ''),
                        'Country': log.get('log_country', ''),
                        'Roles': log.get('log_roles', ''),
                        'Message': log.get('log_message', '').replace('\n', ' ').replace('\r', ''),
                        'SourceFile': log.get('source_file', ''),
                        'FileType': log.get('file_type', ''),
                        'LogInfo': log_info_str
                    }
                    writer.writerow(row)
            
            print(f"Successfully exported {len(self.extracted_logs)} logs to: {self.output_csv}")
            
        except Exception as e:
            print(f"Error exporting to CSV: {e}")

    def print_statistics(self):
        """Print counts and simple breakdowns for the current run."""
        print("\n" + "=" * 60)
        print("PROCESSING STATISTICS")
        print("=" * 60)
        print(f"Files processed: {self.stats['files_processed']}")
        print(f"Total logs found: {self.stats['total_logs_found']}")
        print(f"Target logs extracted: {self.stats['target_logs_extracted']}")
        print(f"Time-window filtered out: {self.stats['time_filtered_out']}")
        print(f"Location filtered out: {self.stats['location_filtered_out']}")
        print(f"INFO/DEBUG logs excluded: {self.stats['info_logs_excluded']}")
        print(f"JSON parse errors: {self.stats['json_parse_errors']}")
        print(f"Unparseable lines: {self.stats['unparseable_lines']}")
        
        # Log level breakdown
        level_counts = {}
        for log in self.extracted_logs:
            level = log.get('log_level', 'UNKNOWN')
            level_counts[level] = level_counts.get(level, 0) + 1
        
        print("\nLog Level Breakdown:")
        for level, count in sorted(level_counts.items()):
            print(f"  {level}: {count}")
        
        # File type breakdown
        file_type_counts = {}
        for log in self.extracted_logs:
            file_type = log.get('file_type', 'UNKNOWN')
            file_type_counts[file_type] = file_type_counts.get(file_type, 0) + 1
        
        print("\nFile Type Breakdown:")
        for file_type, count in sorted(file_type_counts.items()):
            print(f"  {file_type}: {count}")

    def run(self):
        """Run full pipeline: scan, parse, filter, export, and report."""
        start_time = datetime.now()
        
        print("SCM Log Extractor")
        print("=" * 60)
        print(f"Target directory: {self.scm_directory}")
        print(f"Output CSV: {self.output_csv}")
        print(f"Target log levels: {', '.join(self.target_levels)}")
        print(f"Excluded log levels: INFO, DEBUG")
        print(f"Note: Only ERROR, WARN, CRITICAL, FATAL, and SEVERE logs will be extracted")
        if getattr(self, 'start_dt', None) or getattr(self, 'end_dt', None):
            print(f"Time window: start={self.start_dt.isoformat() if self.start_dt else 'None'}, end={self.end_dt.isoformat() if self.end_dt else 'None'}")
        else:
            print("Time window: not set (processing all timestamps)")
        if self.filter_city or self.filter_server:
            print(f"Location filter: city={self.filter_city or 'Any'}, server={self.filter_server or 'Any'}")
        else:
            print("Location filter: not set (processing all locations)")
        print(f"Start time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Process all log files
        self.process_directory()
        
        # Export to CSV
        self.export_to_csv()
        
        # Print statistics
        self.print_statistics()
        
        end_time = datetime.now()
        duration = end_time - start_time
        
        print(f"\nTotal execution time: {duration}")
        print("=" * 60)


def main():
    """CLI entrypoint: optional args override env, then run extractor."""
    # Configuration
    scm_directory = "Error Files/scm/scm"
    output_csv = "technical-2025-09-05.csv"

    # Optional CLI args:
    #   arg1=start (ISO-8601), arg2=end (ISO-8601), arg3=city (lyon/singapore), arg4=server (1/2)
    # Usage examples:
    #   python scm_log_extractor.py 2025-08-12T00:00:00 2025-08-12T23:59:59 lyon 1
    #   python scm_log_extractor.py 2025-08-12T00:00:00 2025-08-12T23:59:59
    #   python scm_log_extractor.py "" "" singapore 2
    start_arg = sys.argv[1] if len(sys.argv) >= 2 else None
    end_arg = sys.argv[2] if len(sys.argv) >= 3 else None
    city_arg = sys.argv[3] if len(sys.argv) >= 4 else None
    server_arg = sys.argv[4] if len(sys.argv) >= 5 else None

    # Allow CLI args to override environment variables if provided
    if start_arg:
        os.environ['EXTRACT_START'] = start_arg
    if end_arg:
        os.environ['EXTRACT_END'] = end_arg
    if city_arg:
        os.environ['EXTRACT_CITY'] = city_arg
    if server_arg:
        os.environ['EXTRACT_SERVER'] = server_arg

    # Check if directory exists
    if not os.path.exists(scm_directory):
        print(f"Error: Directory '{scm_directory}' not found!")
        return
    
    # Create extractor and run
    extractor = SCMLogExtractor(scm_directory, output_csv)
    extractor.run()


if __name__ == "__main__":
    main()
