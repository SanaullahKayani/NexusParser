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
# Paths and class names
UNIX_PATH_RE = re.compile(r"(?:(?<![A-Za-z]):/|/)[^\s,:;\]]+")
WINDOWS_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\s,:;\]]+")
FQ_CLASS_RE = re.compile(r"\b(?:[a-z_][\w]*\.)+([A-Z][\w$]+)\b")
STACKTRACE_PREFIX_RE = re.compile(r"\bstacktrace=")
GENERIC_AT_HEX_RE = re.compile(r"@([0-9a-fA-F]{6,})\b")
BEAN_HASH_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_$]*)#([0-9a-fA-F]{4,})\b")
RABBIT_CONN_RE = re.compile(r"\b(rabbitConnectionFactory)#([0-9a-fA-F]{4,}):(\d+)/SimpleConnection@([0-9a-fA-F]{4,})\b")
# General rabbitConnectionFactory variants (collapse all to <rabbitConnectionFactory>)
RABBIT_ANY_RE = re.compile(r"\brabbitConnectionFactory(?:#[0-9a-fA-F]+)?(?::\d+)?(?:/SimpleConnection@[0-9a-fA-F]+)?\b")
# Remove any trailing suffix after canonical token
RABBIT_TOKEN_TRAIL_RE = re.compile(r"(<rabbitConnectionFactory>)(?::[^\s\]]+)?")
# Threads
ON_THREAD_RE = re.compile(r"\bon thread [^,]+", re.IGNORECASE)
EXEC_THREAD_NUM_RE = re.compile(r"\b(exec|ForkJoinPool-[^\s]+-worker|pool-\d+-thread|nio-\d+|https?-jsse-[^\s,]+-exec)-\d+\b", re.IGNORECASE)
# Server IDs (e.g., VSLSCMMSV101, VSLSCMMSV102, VSLSCMMSV301, VSLSCMMSV302)
SERVER_ID_RE = re.compile(r"\bVSLSCMMSV\d{3}\b", re.IGNORECASE)
QUEUE_ID_WITH_COLON_RE = re.compile(r"\b[0-9A-F]{9,12}:", re.IGNORECASE)
POSTFIX_PROC_RE = re.compile(r"\bpostfix-(receiver|sender)/(?:[a-z-]+)\[\d+\]", re.IGNORECASE)
POSTFIX_PROC_PATH_FIX_RE = re.compile(r"\bpostfix-(receiver|sender)<PATH>\]", re.IGNORECASE)
DOUBLE_EMAIL_FIX_RE = re.compile(r"<<EMAIL>>")
# SQL queries (collapse to <QUERY>) including bracketed forms
BRACKETED_SQL_RE = re.compile(r"\[(?:select|insert|update|delete)[\s\S]*?\]", re.IGNORECASE)
SQL_VERB_RE = re.compile(r"\b(?:select|insert|update|delete)\b[\s\S]*?(?=\)|\]|$)", re.IGNORECASE)

WHITESPACE_RE = re.compile(r"\s+")

# Domain-specific normalizers to reduce duplicates
BRACKET_CTX_PREFIX_RE = re.compile(r"^\[[^\]]+\]\s+")
CONN_WRAPPER_HEX_RE = re.compile(r"ConnectionWrapper@([0-9a-fA-F]+)")
JAVA_PID_RE = re.compile(r"\b(INFO|WARN|ERROR|DEBUG|TRACE)\s+\d+\s+---")
JAVA_PROC_BRACKET_PID_RE = re.compile(r"java\[\d+\]")
USER_NO_OFFICE_RE = re.compile(r"(Cannot find matching office for user )[^\s,]+")
# Vault path masking inside RequestedSecret path
VAULT_SECRET_PATH_RE = re.compile(r"(RequestedSecret \[path=')kv/approle/roles/nexus/staging/DC1/scm-api(?:/[^']+)?('])", re.IGNORECASE)
# Normalize L:/IP:PORT and R:host/IP:PORT port numbers to <NUM>
L_ADDR_PORT_RE = re.compile(r"(L:/)(?:\d{1,3}\.){3}\d{1,3}:(\d+)")
R_ADDR_PORT_RE = re.compile(r"(R:[^/]+/)(?:\d{1,3}\.){3}\d{1,3}:(\d+)")
# Generic patterns
QUOTED_SINGLE_RE = re.compile(r"'[^']*'")
QUOTED_DOUBLE_RE = re.compile(r'"[^"]*"')
# Normalize milliseconds with optional space/decimals, e.g., "5852 ms", "32ms", "2.5 ms"
DURATION_MS_RE = re.compile(r"\b\d+(?:\.\d+)?\s*ms\b", re.IGNORECASE)
PORT_SUFFIX_RE = re.compile(r":\d+\b")
METRICS_KV_NUM_RE = re.compile(r"\b(total|active|idle|waiting|size|connections|threads|count|pool|queue|timeout|retries|retry|attempts|commands|nrcpt)=(\d+)\b", re.IGNORECASE)
# Generic startup timing patterns (language-agnostic structure)
IN_SECONDS_GENERIC_RE = re.compile(r"\bin\s+([0-9]+(?:\.[0-9]+)?)\s*seconds?\b", re.IGNORECASE)
PARENS_FOR_NUMBER_RE = re.compile(r"\(([^)]*?\bfor\s+)([0-9]+(?:\.[0-9]+)?)\)", re.IGNORECASE)

EXPECTED_FIELDS = [
	'Timestamp','Level','Message'
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
	# 1) Remove leading Reactor/Netty bracket context like: "[c194f82e-9, L:/127.0.0.1:33842 ! R:localhost/127.0.0.1:8888] "
	text = BRACKET_CTX_PREFIX_RE.sub('', text)
	# 2) Normalize L:/IP:PORT and R:host/IP:PORT to hide ephemeral ports
	text = L_ADDR_PORT_RE.sub(r"\1<IP>:<NUM>", text)
	text = R_ADDR_PORT_RE.sub(r"\1<IP>:<NUM>", text)
	# 3) Mask ConnectionWrapper hex ids
	text = CONN_WRAPPER_HEX_RE.sub("ConnectionWrapper@<HEX>", text)
	# 4) Remove java[PID] tokens in syslog-like prefaces
	text = JAVA_PROC_BRACKET_PID_RE.sub("java[<NUM>]", text)
	# 5) Normalize logger line header "WARN 1723072 ---" -> "WARN <NUM> ---"
	text = JAVA_PID_RE.sub(lambda m: f"{m.group(1)} <NUM> ---", text)
	# 6) Canonicalize vault RequestedSecret paths to base service
	text = VAULT_SECRET_PATH_RE.sub(r"\1kv/approle/roles/nexus/staging/DC1/scm-api\2", text)
	# 7) Collapse username specifics in "Cannot find matching office for user ..."
	text = USER_NO_OFFICE_RE.sub(r"\1<USER>", text)
	# 8) Normalize durations like 10000ms / 32 ms / 2.5 ms
	text = DURATION_MS_RE.sub('<NUM> ms', text)
	# 8b) Normalize pool metrics key=value numbers
	text = METRICS_KV_NUM_RE.sub(lambda m: f"{m.group(1)}=<NUM>", text)
	# 8c) Normalize generic "in <num> seconds" phrases and parenthetical "for <num>"
	text = IN_SECONDS_GENERIC_RE.sub('in <NUM> seconds', text)
	text = PARENS_FOR_NUMBER_RE.sub(lambda m: f"({m.group(1)}<NUM>)", text)
	# 9) Replace quoted strings with tokens to collapse minor value differences
	text = QUOTED_SINGLE_RE.sub("'<STR>'", text)
	text = QUOTED_DOUBLE_RE.sub('"<STR>"', text)
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
	# 10) Canonicalize rabbit connection patterns EARLY -> <rabbitConnectionFactory>
	text = RABBIT_CONN_RE.sub('<rabbitConnectionFactory>', text)
	text = RABBIT_ANY_RE.sub('<rabbitConnectionFactory>', text)
	text = RABBIT_TOKEN_TRAIL_RE.sub(r"\1", text)
	# 11) Canonicalize paths (Unix/Windows) to <PATH>
	text = UNIX_PATH_RE.sub('<PATH>', text)
	text = WINDOWS_PATH_RE.sub('<PATH>', text)
	# 11a) Normalize postfix process segments to postfix-<role>/<PROC>
	text = POSTFIX_PROC_RE.sub(lambda m: f"postfix-{m.group(1)}/<PROC>", text)
	text = POSTFIX_PROC_PATH_FIX_RE.sub(lambda m: f"postfix-{m.group(1)}/<PROC>]", text)
	# 12) Reduce fully-qualified class names to simple class names
	text = FQ_CLASS_RE.sub(lambda m: m.group(1), text)
	# 13) Remove explicit 'stacktrace=' prefixes
	text = STACKTRACE_PREFIX_RE.sub('', text)
	# 14) Canonicalize hex ids after '@' to @<HEX>
	text = GENERIC_AT_HEX_RE.sub('@<HEX>', text)
	# 15) Canonicalize bean hash suffixes like bean#1462b84 -> bean#<HEX>
	text = BEAN_HASH_RE.sub(lambda m: f"{m.group(1)}#<HEX>", text)
	# 16) Collapse SQL queries to <QUERY>
	text = BRACKETED_SQL_RE.sub('<QUERY>', text)
	# As a fallback, collapse standalone SQL starting with verbs
	text = SQL_VERB_RE.sub('<QUERY>', text)
	# 17) Collapse varying thread identifiers
	text = ON_THREAD_RE.sub('on thread <THREAD>', text)
	text = EXEC_THREAD_NUM_RE.sub('<THREAD>', text)
	# 18) Canonicalize server identifiers
	text = SERVER_ID_RE.sub('<SERVER>', text)
	# 19) Canonicalize queue IDs like 05E19200234:
	text = QUEUE_ID_WITH_COLON_RE.sub('<QUEUE_ID>:', text)
	# 20) Normalize metrics delay/delays numeric sequences to <NUM>
	METRICS_DELAY_RE = re.compile(r"\b(delay|delays)=([0-9]+(?:\.[0-9]+)?(?:/[0-9]+(?:\.[0-9]+)?){0,3})\b", re.IGNORECASE)
	def _normalize_delays(m):
		key = m.group(1).lower()
		seq = m.group(2)
		parts = seq.split('/')
		return f"{key}=" + "/".join(['<NUM>' for _ in parts])
	text = METRICS_DELAY_RE.sub(_normalize_delays, text)
	# 21) Fix accidental double tokenization of EMAIL
	text = DOUBLE_EMAIL_FIX_RE.sub('<EMAIL>', text)
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
	"""Compute a stable signature using only level and canonical message; returns (hex_digest, canonical_message)."""
	level = (row.get('Level') or row.get('LogLevel') or '').upper()
	canon_msg = canonicalize_message(row.get('Message') or '')
	base = '\n'.join([level, canon_msg])
	digest = hashlib.sha1(base.encode('utf-8', errors='ignore')).hexdigest()
	return digest, canon_msg


# Aggregator
class Group:
	__slots__ = (
		'fingerprint','level','canonical_message','example_message','count','first_seen','last_seen'
	)
	def __init__(self, fingerprint: str, row: Dict[str,str], canonical_message: str):
		self.fingerprint = fingerprint
		self.level = (row.get('Level') or row.get('LogLevel') or '').strip()
		self.canonical_message = canonical_message
		self.example_message = (row.get('Message') or '').strip()
		self.count = 1
		self.first_seen = row.get('Timestamp') or ''
		self.last_seen = row.get('Timestamp') or ''

	def update(self, row: Dict[str,str]):
		self.count += 1
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
		missing = [c for c in EXPECTED_FIELDS if c not in (reader.fieldnames or [])]
		if missing:
			raise RuntimeError(f"Input CSV missing required columns: {missing}")

		for row in reader:
			stats['rows_read'] += 1
			# Compute signature
			fp, canon_msg = compute_signature(row)
			if fp not in groups:
				groups[fp] = Group(fp, row, canon_msg)
			else:
				groups[fp].update(row)

	# Export deduped CSV
	out_fields = [
		'Fingerprint','Level','CanonicalMessage','ExampleMessage','Occurrences','FirstSeen','LastSeen'
	]
	with open(output_csv, 'w', encoding='utf-8', newline='') as f_out:
		writer = csv.DictWriter(f_out, fieldnames=out_fields)
		writer.writeheader()
		for g in groups.values():
			writer.writerow({
				'Fingerprint': g.fingerprint[:16],
				'Level': g.level,
				'CanonicalMessage': g.canonical_message,
				'ExampleMessage': g.example_message,
				'Occurrences': g.count,
				'FirstSeen': g.first_seen,
				'LastSeen': g.last_seen,
			})

	# Optional JSONL export for LLM ingestion
	if output_jsonl:
		with open(output_jsonl, 'w', encoding='utf-8') as jf:
			for g in groups.values():
				record = {
					'fingerprint': g.fingerprint,
					'level': g.level,
					'canonical_message': g.canonical_message,
					'occurrences': g.count,
					'first_seen': g.first_seen,
					'last_seen': g.last_seen,
					'example': {
						'message': g.example_message
					}
				}
				jf.write(json.dumps(record, ensure_ascii=False) + "\n")

	stats['groups_created'] = len(groups)
	stats['duplicates_removed'] = max(0, stats['rows_read'] - stats['groups_created'])
	return stats


def main():
	input_csv = os.environ.get('SCM_INPUT_CSV', 'technical-2025-09-05_all_clean_minimal.csv')
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
