## Utilities to trim noisy stack traces and keep essential error details in JSONL.

import json
import csv
import re
import sys
from typing import Dict, Any

#Return a concise error string by removing stack traces and framework noise.
def clean_error_message(message: str) -> str:
    
    if not message:
        return message
    
    # Normalize line endings
    message = message.replace('\r\n', '\n').replace('\r', '\n')
    original_message = message

    # First, try to extract the main error message before any stack trace
    main_error_patterns = [
        # Generic cut before common stack-trace markers
        r'^(.+?)(?:\n+Traceback \(most recent call last\):)',
        r'^(.+?)(?:\s+at\s+|\n+at\s+|Suppressed:|Caused by:|Original Stack Trace:)',
        # Java/Framework noise markers
        r'^(.+?)(?:\s+reactor\.core\.publisher|io\.netty|java\.base|org\.springframework|org\.hibernate|com\.zaxxer|org\.apache)',
        # Internal request noise
        r'^(.+?)(?:\s+__checkpoint|Request to POST|Request to GET|Request to PUT|Request to DELETE)',
    ]
    
    for pattern in main_error_patterns:
        match = re.search(pattern, message, re.DOTALL)
        if match:
            message = match.group(1).strip()
            break
    
    # Remove stack-trace style lines or framework noise
    lines = message.split('\n')
    cleaned_lines = []
    first_stack_frame = None
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Skip stack trace lines
        if (
            # Java/JS stack frames
            re.match(r'^(?:\s*at\s+)[\w$_.<>]+\(.*?\)$', line) or
            re.match(r'^(?:\s*at\s+).+?:\d+(?::\d+)?\)?$', line) or
            re.search(r'\(.*?\.(?:java|kt|scala|ts|tsx|js):\d+(?::\d+)?\)', line) or
            re.search(r'\.(?:java|kt|scala|ts|tsx|js):\d+(?::\d+)?$', line) or
            # Python traceback frames
            line.startswith('Traceback (most recent call last):') or
            re.match(r'^File\s+".*",\s+line\s+\d+,\s+in\s+\w+', line) or
            # Common noise prefixes
            line.startswith('Suppressed:') or
            line.startswith('Caused by:') or
            'Original Stack Trace:' in line or
            '__checkpoint' in line or
            'Request to POST' in line or
            'Request to GET' in line or
            'Request to PUT' in line or
            'Request to DELETE' in line or
            'DefaultWebClient' in line or
            'reactor.core.publisher' in line or
            'io.netty' in line or
            'java.base' in line or
            'org.springframework' in line or
            'org.hibernate' in line or
            'com.zaxxer' in line or
            'org.apache' in line or
            'sun.reflect' in line or
            'javax.' in line or
            'kotlin.' in line or
            'scala.' in line
        ):
            # Preserve the first stack frame for context
            if first_stack_frame is None:
                first_stack_frame = line
                # # Prefer explicit 'at ' frames; otherwise any frame-like content
                # if line.startswith('at '):
                #     first_stack_frame = line
                # else:
                #     # Normalize to start with 'at '
                #     first_stack_frame = f"at {line}"
            continue
            
        cleaned_lines.append(line)

    cleaned_message = ' '.join(cleaned_lines)
    cleaned_message = re.sub(r'\s+', ' ', cleaned_message).strip()
    
    # If still long, prefer the main exception or first sentence
    if len(cleaned_message) > 300:
        main_error_match = re.search(r'([A-Za-z]+(?:Exception|Error)[^:]*:?[^:]*?)(?:\s+at\s+|$)', cleaned_message)
        if main_error_match:
            cleaned_message = main_error_match.group(1).strip()
        
        if len(cleaned_message) > 200:
            sentences = re.split(r'[.!?]', cleaned_message)
            if sentences:
                cleaned_message = sentences[0].strip()
                if cleaned_message and not cleaned_message.endswith(('.', '!', '?')):
                    cleaned_message += '.'

    # If message contains a CLEAR logger prefix like "ERROR: real message",
    # keep only the part after the FIRST colon when the prefix looks like a logger token.
    def _is_logger_prefix(prefix: str) -> bool:
        known = {
            'ERROR', 'ERR', 'WARN', 'WARNING', 'INFO', 'DEBUG', 'TRACE',
            'FATAL', 'SEVERE', 'CRITICAL', 'NOTICE'
        }
        if prefix in known:
            return True
        # UPPERCASE identifiers like ROOT, APP, LOGGER, com.company.Logger (avoid trimming those)
        # Only allow trimming when the prefix is short and all-caps tokens
        if len(prefix) <= 20 and re.fullmatch(r'[A-Z][A-Z0-9_.-]*', prefix or ''):
            return True
        return False

    if ':' in cleaned_message:
        first_colon = cleaned_message.find(':')
        prefix = cleaned_message[:first_colon].strip()
        tail = cleaned_message[first_colon + 1 :].strip()
        if _is_logger_prefix(prefix) and len(tail) >= 5:
            cleaned_message = tail

    # Append the first stack frame for essential context, if missing
    if first_stack_frame and ' at ' not in cleaned_message:
        if cleaned_message:
            cleaned_message = f"{cleaned_message} {first_stack_frame}"
        else:
            cleaned_message = first_stack_frame
    
    return cleaned_message.strip()

def clean_canonical_log_info(log_info: str) -> str:
    """Extract key details from canonical_log_info (errors, context, main exception)."""
    if not log_info:
        return log_info
    
    # Try to extract the main database error or key information
    main_patterns = [
        # Database errors
        r'ERROR: ([^\\n]+)',
        r'could not execute statement \[([^\]]+)\]',
        r'could not extend file[^:]*: ([^\\n]+)',
        r'No space left on device',
        r'Database connection failed',
        r'Transaction failed',
        
        # Key context information
        r'x-retry-count:(\d+)',
        r'routingKey:([^;]+)',
        r'owner:([^;]+)',
        
        # Main exception types
        r'([A-Za-z]+Exception[^:]*:?[^:]*?)(?:\s+at\s+|$)',
    ]
    
    extracted_info = []
    
    for pattern in main_patterns:
        matches = re.findall(pattern, log_info, re.IGNORECASE)
        for match in matches:
            if match and len(match.strip()) > 5: 
                extracted_info.append(match.strip())
    

    if extracted_info:
        # Remove duplicates and join
        unique_info = list(dict.fromkeys(extracted_info))
        return ' | '.join(unique_info[:3]) 
    
    # Otherwise, take the first meaningful line that looks useful
    lines = log_info.split('\n')
    for line in lines:
        line = line.strip()
        if line and len(line) > 10 and not line.startswith('at '):
            if any(keyword in line.lower() for keyword in ['error', 'exception', 'failed', 'could not', 'database']):
                return line[:200] + ('...' if len(line) > 200 else '')
    
    # Fallback summary
    return "Detailed stack trace and framework information (cleaned)"
    

#  Clean an entry's message fields in-place and return the entry.
def clean_jsonl_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    
    if 'canonical_message' in entry:
        entry['canonical_message'] = clean_error_message(entry['canonical_message'])

    if 'canonical_log_info' in entry:
        entry['canonical_log_info'] = clean_canonical_log_info(entry['canonical_log_info'])
    
    if 'example' in entry and isinstance(entry['example'], dict):
        if 'message' in entry['example']:
            entry['example']['message'] = clean_error_message(entry['example']['message'])
    
    return entry

def process_jsonl_file(input_file: str, output_file: str = None):
    """Stream-clean a JSONL file; writes cleaned lines to output_file."""
    if output_file is None:
        name, ext = input_file.rsplit('.', 1)
        output_file = f"{name}_cleaned.{ext}"
    
    cleaned_count = 0
    total_count = 0
    
    try:
        with open(input_file, 'r', encoding='utf-8') as infile, \
             open(output_file, 'w', encoding='utf-8') as outfile:
            
            for line_num, line in enumerate(infile, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    entry = json.loads(line)
                    total_count += 1

                    cleaned_entry = clean_jsonl_entry(entry)

                    json.dump(cleaned_entry, outfile, ensure_ascii=False)
                    outfile.write('\n')
                    
                    cleaned_count += 1
                    
                except json.JSONDecodeError as e:
                    print(f"Warning: Could not parse JSON at line {line_num}: {e}")
                    outfile.write(line + '\n')
        
        print(f"Successfully processed {cleaned_count} out of {total_count} entries")
        print(f"Cleaned file saved as: {output_file}")
        
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)

def process_csv_file(input_file: str, output_file: str = None):
    """Stream-clean a CSV file; cleans Message and LogInfo columns if present."""
    if output_file is None:
        if '.' in input_file:
            name, ext = input_file.rsplit('.', 1)
            output_file = f"{name}_cleaned.{ext}"
        else:
            output_file = f"{input_file}_cleaned"

    cleaned_count = 0
    total_count = 0

    try:
        # Increase field size limit to accommodate very large log fields
        try:
            csv.field_size_limit(sys.maxsize)
        except OverflowError:
            csv.field_size_limit(10_000_000)

        with open(input_file, 'r', encoding='utf-8', newline='') as infile, \
             open(output_file, 'w', encoding='utf-8', newline='') as outfile:

            reader = csv.DictReader(infile)
            fieldnames = reader.fieldnames or []
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:
                total_count += 1
                # Clean Message and LogInfo if present
                if 'Message' in row and row['Message']:
                    row['Message'] = clean_error_message(row['Message'])
                if 'LogInfo' in row and row['LogInfo']:
                    row['LogInfo'] = clean_canonical_log_info(row['LogInfo'])

                writer.writerow(row)
                cleaned_count += 1

        print(f"Successfully processed {cleaned_count} out of {total_count} rows")
        print(f"Cleaned file saved as: {output_file}")

    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing CSV file: {e}")
        sys.exit(1)

def main():
    """CLI entrypoint: python clean_error_messages.py <input> [output].

    - If input ends with .jsonl, treats file as JSON Lines and cleans JSON fields
    - If input ends with .csv, cleans CSV columns 'Message' and 'LogInfo' if present
    """
    if len(sys.argv) < 2:
        print("Usage: python clean_error_messages.py <input_file> [output_file]")
        print("Example: python clean_error_messages.py sample.jsonl")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    lower_name = input_file.lower()
    if lower_name.endswith('.jsonl'):
        process_jsonl_file(input_file, output_file)
    elif lower_name.endswith('.csv'):
        process_csv_file(input_file, output_file)
    else:
        # Try JSONL first; if it fails with decode errors on first non-empty line,
        # suggest using the correct extension.
        try:
            process_jsonl_file(input_file, output_file)
        except SystemExit:
            # Re-raise exit for critical errors
            raise
        except Exception:
            print("Unrecognized file type. Please provide a .jsonl or .csv file.")
            sys.exit(1)

if __name__ == "__main__":
    main()
