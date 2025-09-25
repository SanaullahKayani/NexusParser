import csv
import json
import os
import re
import hashlib
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set

# Increase CSV field size limit to handle large log fields
try:
	csv.field_size_limit(sys.maxsize)
except Exception:
	csv.field_size_limit(10**9)


# Helpers: Canonicalization
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
ISO_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?\b")
SYSLOG_TS_RE = re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"https?://\S+")
ANGLE_MSGID_RE = re.compile(r"<[^>]+@[^>]+>")
EASY_NUM_RE = re.compile(r"\b\d{2,}-\d{2,}-\d+-\d+\b")
HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
BIG_NUM_RE = re.compile(r"\b\d{5,}\b")

WHITESPACE_RE = re.compile(r"\s+")

EXPECTED_FIELDS = [
	'Timestamp','LogLevel','LogPurpose','Hostname','Application','Service','Instance','Office','Country','Roles','Message','SourceFile','FileType','LogInfo'
]

TIMESTAMP_FORMATS = [
	"%Y-%m-%dT%H:%M:%S",
	"%Y-%m-%d %H:%M:%S",
	"%Y-%m-%dT%H:%M:%S.%f",
	"%Y-%m-%d %H:%M:%S.%f",
]


def parse_timestamp(value: str) -> Optional[datetime]:
	if not value:
		return None
	# Try ISO 8601 directly
	try:
		return datetime.fromisoformat(value.replace('Z', '+00:00'))
	except Exception:
		pass
	# Try known formats
	for fmt in TIMESTAMP_FORMATS:
		try:
			return datetime.strptime(value, fmt)
		except Exception:
			continue
	return None


def canonicalize_message(message: str) -> str:
	if not message:
		return ""
	text = message
	text = URL_RE.sub('<URL>', text)
	text = EMAIL_RE.sub('<EMAIL>', text)
	text = IPV4_RE.sub('<IP>', text)
	text = UUID_RE.sub('<UUID>', text)
	text = ANGLE_MSGID_RE.sub('<MSG_ID>', text)
	text = EASY_NUM_RE.sub('<EASY_NO>', text)
	text = ISO_TS_RE.sub('<TIMESTAMP>', text)
	text = SYSLOG_TS_RE.sub('<SYSLOG_TS>', text)
	text = HEX_RE.sub('<HEX>', text)
	text = BIG_NUM_RE.sub('<NUM>', text)
	# Normalize whitespace and trim
	text = WHITESPACE_RE.sub(' ', text).strip()
	return text


def canonicalize_loginformation(log_info: str) -> str:
	"""Normalize LogInfo column which may be a semicolon-separated name:value pairs or raw text."""
	if not log_info:
		return ""
	# If JSON-like, try to parse, else return normalized spaces
	candidate = log_info.strip()
	if candidate.startswith('[') or candidate.startswith('{'):
		try:
			parsed = json.loads(candidate)
			if isinstance(parsed, list):
				pairs = []
				for item in parsed:
					if isinstance(item, dict):
						name = str(item.get('name','')).strip()
						value = str(item.get('value','')).strip()
						pairs.append((name, canonicalize_message(value)))
				pairs.sort(key=lambda x: x[0])
				return '; '.join([f"{k}:{v}" for k,v in pairs])
			return canonicalize_message(candidate)
		except Exception:
			return canonicalize_message(candidate)
	return canonicalize_message(candidate)


def compute_signature(row: Dict[str, str]) -> Tuple[str, str]:
	"""Compute a stable signature from meaningful fields; returns (hex_digest, canonical_message)."""
	purpose = (row.get('LogPurpose') or '').upper()
	level = (row.get('LogLevel') or '').upper()
	app = (row.get('Application') or '').lower()
	service = (row.get('Service') or '').lower()
	canon_msg = canonicalize_message(row.get('Message') or '')
	canon_info = canonicalize_loginformation(row.get('LogInfo') or '')
	base = '\n'.join([purpose, level, app, service, canon_msg, canon_info])
	digest = hashlib.sha1(base.encode('utf-8', errors='ignore')).hexdigest()
	return digest, canon_msg


# Aggregator
class Group:
	__slots__ = (
		'fingerprint','purpose','level','application','service','canonical_message','canonical_info',
		'example_message','example_source','roles','hosts','sources','count','first_seen','last_seen'
	)
	def __init__(self, fingerprint: str, row: Dict[str,str], canonical_message: str, canonical_info: str):
		self.fingerprint = fingerprint
		self.purpose = (row.get('LogPurpose') or '').strip()
		self.level = (row.get('LogLevel') or '').strip()
		self.application = (row.get('Application') or '').strip()
		self.service = (row.get('Service') or '').strip()
		self.canonical_message = canonical_message
		self.canonical_info = canonical_info
		self.example_message = (row.get('Message') or '').strip()
		self.example_source = (row.get('SourceFile') or '').strip()
		self.roles: Set[str] = set(filter(None, [(row.get('Roles') or '').strip()]))
		self.hosts: Set[str] = set(filter(None, [(row.get('Hostname') or '').strip()]))
		self.sources: Set[str] = set(filter(None, [(row.get('SourceFile') or '').strip()]))
		self.count = 1
		self.first_seen = row.get('Timestamp') or ''
		self.last_seen = row.get('Timestamp') or ''

	def update(self, row: Dict[str,str]):
		self.count += 1
		role = (row.get('Roles') or '').strip()
		if role:
			self.roles.add(role)
		host = (row.get('Hostname') or '').strip()
		if host:
			self.hosts.add(host)
		src = (row.get('SourceFile') or '').strip()
		if src:
			self.sources.add(src)
		# Update first/last seen via timestamp comparison if possible
		curr_ts = row.get('Timestamp') or ''
		self.first_seen, self.last_seen = update_time_bounds(self.first_seen, self.last_seen, curr_ts)


def update_time_bounds(first: str, last: str, candidate: str) -> Tuple[str,str]:
	def better(a: Optional[datetime], b: Optional[datetime], pick_min: bool) -> Optional[datetime]:
		if a is None:
			return b
		if b is None:
			return a
		return min(a,b) if pick_min else max(a,b)
	fa = parse_timestamp(first)
	la = parse_timestamp(last)
	cb = parse_timestamp(candidate)
	new_first = better(fa, cb, True)
	new_last = better(la, cb, False)
	# Fallback: lexicographical if both None
	if new_first is None:
		new_first = cb
	if new_last is None:
		new_last = cb
	return (new_first.isoformat() if new_first else first or candidate,
			new_last.isoformat() if new_last else last or candidate)


## Main processing
def preprocess_csv_for_llm(input_csv: str, output_csv: str, output_jsonl: Optional[str] = None) -> Dict[str, Any]:
	stats = {
		'rows_read': 0,
		'groups_created': 0,
		'duplicates_removed': 0
	}
	groups: Dict[str, Group] = {}

	with open(input_csv, 'r', encoding='utf-8', newline='') as f:
		reader = csv.DictReader(f)
		missing = [c for c in EXPECTED_FIELDS if c not in reader.fieldnames]
		if missing:
			raise RuntimeError(f"Input CSV missing required columns: {missing}")

		for row in reader:
			stats['rows_read'] += 1
			# Compute signature
			fp, canon_msg = compute_signature(row)
			canon_info = canonicalize_loginformation(row.get('LogInfo') or '')
			if fp not in groups:
				groups[fp] = Group(fp, row, canon_msg, canon_info)
			else:
				groups[fp].update(row)

	# Export deduped CSV
	out_fields = [
		'Fingerprint','LogPurpose','LogLevel','Application','Service','CanonicalMessage','CanonicalLogInfo',
		'ExampleMessage','Occurrences','FirstSeen','LastSeen','HostCount','HostsSample','SourceCount','SourcesSample','Roles'
	]
	with open(output_csv, 'w', encoding='utf-8', newline='') as f_out:
		writer = csv.DictWriter(f_out, fieldnames=out_fields)
		writer.writeheader()
		for g in groups.values():
			hosts_sample = ", ".join(sorted(list(g.hosts))[:5])
			sources_sample = ", ".join(sorted(list(g.sources))[:5])
			roles_joined = ", ".join(sorted(list(g.roles)))
			writer.writerow({
				'Fingerprint': g.fingerprint[:16],
				'LogPurpose': g.purpose,
				'LogLevel': g.level,
				'Application': g.application,
				'Service': g.service,
				'CanonicalMessage': g.canonical_message,
				'CanonicalLogInfo': g.canonical_info,
				'ExampleMessage': g.example_message,
				'Occurrences': g.count,
				'FirstSeen': g.first_seen,
				'LastSeen': g.last_seen,
				'HostCount': len(g.hosts),
				'HostsSample': hosts_sample,
				'SourceCount': len(g.sources),
				'SourcesSample': sources_sample,
				'Roles': roles_joined,
			})

	# Optional JSONL export for LLM ingestion
	if output_jsonl:
		with open(output_jsonl, 'w', encoding='utf-8') as jf:
			for g in groups.values():
				record = {
					'fingerprint': g.fingerprint,
					'purpose': g.purpose,
					'level': g.level,
					'application': g.application,
					'service': g.service,
					'canonical_message': g.canonical_message,
					'canonical_log_info': g.canonical_info,
					'occurrences': g.count,
					'first_seen': g.first_seen,
					'last_seen': g.last_seen,
					'hosts': sorted(list(g.hosts))[:50],
					'sources': sorted(list(g.sources))[:50],
					'roles': sorted(list(g.roles)),
					'example': {
						'message': g.example_message,
						'source': g.example_source
					}
				}
				jf.write(json.dumps(record, ensure_ascii=False) + "\n")

	stats['groups_created'] = len(groups)
	stats['duplicates_removed'] = max(0, stats['rows_read'] - stats['groups_created'])
	return stats


def main():
	input_csv = os.environ.get('SCM_INPUT_CSV', 'scm_error_warn_logs_cleaned.csv')
	output_csv = os.environ.get('SCM_OUTPUT_CSV', 'scm_logs_llm_ready.csv')
	output_jsonl = os.environ.get('SCM_OUTPUT_JSONL', 'scm_logs_llm_ready.jsonl')

	print("Preprocessing logs for LLM ingestion")
	print("=" * 60)
	print(f"Input:  {input_csv}")
	print(f"Output: {output_csv}")
	print(f"JSONL:  {output_jsonl}")
	print("=" * 60)

	stats = preprocess_csv_for_llm(input_csv, output_csv, output_jsonl)
	print("Done. Summary:")
	print(f"  Rows read:           {stats['rows_read']}")
	print(f"  Groups created:      {stats['groups_created']}")
	print(f"  Duplicates removed:  {stats['duplicates_removed']}")


if __name__ == '__main__':
	main()
