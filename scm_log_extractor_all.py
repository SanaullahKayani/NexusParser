"""
SCM Log Extractor (All Levels): extracts ALL log levels including INFO/DEBUG.
Optional time and location filters; writes a normalized CSV similar to scm_log_extractor.py
"""

import json
import csv
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional


class SCMLogExtractorAll:
    def __init__(self, scm_directory: str, output_csv: str):
        self.scm_directory = Path(scm_directory)
        self.output_csv = output_csv
        self.extracted_logs: List[Dict[str, Any]] = []

        # For information only; not used to filter
        self.known_levels = ['TRACE', 'DEBUG', 'INFO', 'WARN', 'WARNING', 'ERROR', 'CRITICAL', 'FATAL', 'SEVERE']

        # Track processing statistics
        self.stats = {
            'files_processed': 0,
            'total_logs_found': 0,
            'logs_collected': 0,
            'time_filtered_out': 0,
            'location_filtered_out': 0,
            'json_parse_errors': 0,
            'unparseable_lines': 0
        }

        # Optional time window filtering (inclusive) via environment variables
        self.start_time_str = os.environ.get('EXTRACT_START', '').strip()
        self.end_time_str = os.environ.get('EXTRACT_END', '').strip()
        self.start_dt: Optional[datetime] = self._parse_iso_ts(self.start_time_str) if self.start_time_str else None
        self.end_dt: Optional[datetime] = self._parse_iso_ts(self.end_time_str) if self.end_time_str else None

        # Optional location filters via environment variables
        self.filter_city_raw = os.environ.get('EXTRACT_CITY', '').strip()
        self.filter_server_raw = os.environ.get('EXTRACT_SERVER', '').strip()
        self.filter_city = self._normalize_city(self.filter_city_raw) if self.filter_city_raw else None
        self.filter_server = self._normalize_server(self.filter_server_raw) if self.filter_server_raw else None

    def _normalize_city(self, value: str) -> Optional[str]:
        v = value.strip().lower()
        if not v:
            return None
        if v.startswith('lyon'):
            return 'lyon'
        if v.startswith('sing'):
            return 'singapore'
        return v

    def _normalize_server(self, value: str) -> Optional[str]:
        v = value.strip().lower()
        if not v:
            return None
        m = re.search(r'(?:server|srv)?\s*(\d)', v)
        if m:
            return m.group(1)
        return v

    def _extract_site_info(self, source_or_host: str) -> (Optional[str], Optional[str]):
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
        try:
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                return json.loads(line)
            return None
        except json.JSONDecodeError:
            self.stats['json_parse_errors'] += 1
            return None

    def parse_multi_line_json(self, lines: List[str]) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        current_json_lines: List[str] = []
        for line in lines:
            line = line.strip()
            if line.startswith('{'):
                if current_json_lines:
                    try:
                        combined = ''.join(current_json_lines)
                        logs.append(json.loads(combined))
                    except json.JSONDecodeError:
                        self.stats['json_parse_errors'] += 1
                current_json_lines = [line]
            elif line.endswith('}') and current_json_lines:
                current_json_lines.append(line)
                try:
                    combined = ''.join(current_json_lines)
                    logs.append(json.loads(combined))
                except json.JSONDecodeError:
                    self.stats['json_parse_errors'] += 1
                current_json_lines = []
            elif current_json_lines:
                current_json_lines.append(line)
        if current_json_lines:
            try:
                combined = ''.join(current_json_lines)
                logs.append(json.loads(combined))
            except json.JSONDecodeError:
                self.stats['json_parse_errors'] += 1
        return logs

    def parse_traditional_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        line = line.strip()
        if not line:
            return None
        log_entry: Dict[str, Any] = {
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
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
        if timestamp_match:
            log_entry['log_timestamp'] = timestamp_match.group(1)
        level_patterns = [
            r'\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL|SEVERE)\b',
            r'\[(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL|SEVERE)\]',
            r'level="(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL|SEVERE)"'
        ]
        for pattern in level_patterns:
            level_match = re.search(pattern, line, re.IGNORECASE)
            if level_match:
                log_entry['log_level'] = level_match.group(1).upper()
                break
        hostname_match = re.search(r'(\w+\.\w+\.\w+)', line)
        if hostname_match:
            log_entry['log_hostname'] = hostname_match.group(1)
        return log_entry

    def process_json_log_file(self, file_path: Path) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()
            for line in lines:
                log_entry = self.parse_json_log_line(line)
                if log_entry:
                    logs.append(log_entry)
                    self.stats['total_logs_found'] += 1
            if not logs:
                logs = self.parse_multi_line_json(lines)
                self.stats['total_logs_found'] += len(logs)
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
        return logs

    def process_traditional_log_file(self, file_path: Path) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
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
        filename = file_path.name.lower()
        if any(keyword in filename for keyword in ['technical', 'audit', 'statistics']):
            return 'json'
        if any(keyword in filename for keyword in ['postfix', 'nginx', 'access', 'error', 'journal', 'maillog', 'var.log']):
            return 'traditional'
        return 'json'

    def process_log_file(self, file_path: Path) -> List[Dict[str, Any]]:
        file_type = self.determine_file_type(file_path)
        if file_type == 'json':
            logs = self.process_json_log_file(file_path)
        else:
            logs = self.process_traditional_log_file(file_path)
        for log in logs:
            log['source_file'] = str(file_path)
            log['file_type'] = file_type
        return logs

    def collect_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply only time/location filters; keep ALL levels including INFO/DEBUG."""
        kept: List[Dict[str, Any]] = []
        for log in logs:
            if not self._is_within_time_range(log):
                self.stats['time_filtered_out'] += 1
                continue
            if not self._passes_location_filter(log):
                self.stats['location_filtered_out'] += 1
                continue
            kept.append(log)
        self.stats['logs_collected'] += len(kept)
        return kept

    def process_directory(self):
        print(f"Starting to process SCM directory: {self.scm_directory}")
        print("=" * 60)
        for root, dirs, files in os.walk(self.scm_directory):
            root_path = Path(root)
            for file in files:
                if file.endswith('.log') or file.endswith('.txt'):
                    file_path = root_path / file
                    try:
                        if file_path.stat().st_size == 0:
                            continue
                        print(f"Processing: {file_path}")
                        logs = self.process_log_file(file_path)
                        kept = self.collect_logs(logs)
                        self.extracted_logs.extend(kept)
                        self.stats['files_processed'] += 1
                        print(f"  ✓ Kept {len(kept)} logs")
                    except Exception as e:
                        print(f"  ✗ Error processing {file_path}: {e}")
                        continue
        print("=" * 60)
        print("Processing complete!")

    def export_to_csv(self):
        if not self.extracted_logs:
            print("No logs to export!")
            return
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
                        'Message': (log.get('log_message', '') or '').replace('\n', ' ').replace('\r', ''),
                        'SourceFile': log.get('source_file', ''),
                        'FileType': log.get('file_type', ''),
                        'LogInfo': log_info_str
                    }
                    writer.writerow(row)
            print(f"Successfully exported {len(self.extracted_logs)} logs to: {self.output_csv}")
        except Exception as e:
            print(f"Error exporting to CSV: {e}")

    def print_statistics(self):
        print("\n" + "=" * 60)
        print("PROCESSING STATISTICS (ALL LEVELS)")
        print("=" * 60)
        print(f"Files processed: {self.stats['files_processed']}")
        print(f"Total logs found: {self.stats['total_logs_found']}")
        print(f"Logs collected: {self.stats['logs_collected']}")
        print(f"Time-window filtered out: {self.stats['time_filtered_out']}")
        print(f"Location filtered out: {self.stats['location_filtered_out']}")
        print(f"JSON parse errors: {self.stats['json_parse_errors']}")
        print(f"Unparseable lines: {self.stats['unparseable_lines']}")
        level_counts: Dict[str, int] = {}
        for log in self.extracted_logs:
            level = (log.get('log_level') or 'UNKNOWN').upper()
            level_counts[level] = level_counts.get(level, 0) + 1
        print("\nLog Level Breakdown:")
        for level, count in sorted(level_counts.items()):
            print(f"  {level}: {count}")
        file_type_counts: Dict[str, int] = {}
        for log in self.extracted_logs:
            file_type = log.get('file_type', 'UNKNOWN')
            file_type_counts[file_type] = file_type_counts.get(file_type, 0) + 1
        print("\nFile Type Breakdown:")
        for file_type, count in sorted(file_type_counts.items()):
            print(f"  {file_type}: {count}")

    def run(self):
        start_time = datetime.now()
        print("SCM Log Extractor (All Levels)")
        print("=" * 60)
        print(f"Target directory: {self.scm_directory}")
        print(f"Output CSV: {self.output_csv}")
        print("Note: All log levels (including INFO/DEBUG) will be collected")
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
        self.process_directory()
        self.export_to_csv()
        self.print_statistics()
        end_time = datetime.now()
        duration = end_time - start_time
        print(f"\nTotal execution time: {duration}")
        print("=" * 60)


def main():
    """CLI entrypoint for all-level extractor."""
    scm_directory = "Error Files/scm/scm"
    output_csv = "technical-2025-09-05_all.csv"

    # Optional CLI args:
    #   arg1=start (ISO-8601), arg2=end (ISO-8601), arg3=city (lyon/singapore), arg4=server (1/2)
    # Usage examples:
    #   python scm_log_extractor_all.py 2025-08-12T00:00:00 2025-08-12T23:59:59 lyon 1
    #   python scm_log_extractor_all.py 2025-08-12T00:00:00 2025-08-12T23:59:59
    #   python scm_log_extractor_all.py "" "" singapore 2
    start_arg = sys.argv[1] if len(sys.argv) >= 2 else None
    end_arg = sys.argv[2] if len(sys.argv) >= 3 else None
    city_arg = sys.argv[3] if len(sys.argv) >= 4 else None
    server_arg = sys.argv[4] if len(sys.argv) >= 5 else None

    if start_arg:
        os.environ['EXTRACT_START'] = start_arg
    if end_arg:
        os.environ['EXTRACT_END'] = end_arg
    if city_arg:
        os.environ['EXTRACT_CITY'] = city_arg
    if server_arg:
        os.environ['EXTRACT_SERVER'] = server_arg

    if not os.path.exists(scm_directory):
        print(f"Error: Directory '{scm_directory}' not found!")
        return

    extractor = SCMLogExtractorAll(scm_directory, output_csv)
    extractor.run()


if __name__ == "__main__":
    main()


