from Drain import LogParser

rex = [
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?',
    r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{2}\s+\d{2}:\d{2}:\d{2}',
    r'\[\d+\]',
    r'\b\d{1,3}(?:\.\d{1,3}){3}\b',
    r'<[^>]+@[^>]+>',
    r'\bv?\d+(?:\.\d+)+\b',
    r'0x[0-9a-fA-F]+',
    r':\d{2,5}',
]

# Treat entire line as content
log_format = '<Content>'

# Journalctl file
parser1 = LogParser(log_format=log_format, indir='logs', outdir='result', depth=4, st=0.4, rex=rex, keep_para=True)
parser1.parse('journalctl-api-20250905.log')

# JSON-lines technical file
parser2 = LogParser(log_format=log_format, indir='logs', outdir='result', depth=4, st=0.4, rex=rex, keep_para=True)
parser2.parse('technical-2025-09-05.log')