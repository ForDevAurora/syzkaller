#!/usr/bin/env python3
"""
Parse analyze_complex_types output and convert to syscall list JSON.

Usage:
    # From text output
    ./analyze_complex_types -calls=sendmsg -output-format=text | python3 parse_output.py

    # From JSON output
    ./analyze_complex_types -calls=sendmsg -output-format=json | python3 parse_output.py --format=json

    # From file
    python3 parse_output.py --input=output.txt
    python3 parse_output.py --input=output.json --format=json

    # Save to file
    python3 parse_output.py --input=output.txt --output=syscalls.json
"""

import sys
import json
import argparse
import re


def parse_text_output(content):
    """Parse text format output from analyze_complex_types."""
    syscalls = []

    # Split into lines
    lines = content.strip().split('\n')

    # Look for syscall names after "- " prefix
    for line in lines:
        line = line.strip()
        # Match lines like "  - sendmsg$inet"
        if line.startswith('- '):
            syscall_name = line[2:].strip()
            # Skip empty lines and section headers
            if syscall_name and '(' not in syscall_name:
                syscalls.append(syscall_name)

    return syscalls


def parse_json_output(content):
    """Parse JSON format output from analyze_complex_types."""
    try:
        data = json.loads(content)

        # Extract syscall names from calls array
        syscalls = []
        if 'calls' in data:
            for call in data['calls']:
                if 'name' in call:
                    syscalls.append(call['name'])

        return syscalls
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Parse analyze_complex_types output to syscall list JSON',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        '--input', '-i',
        help='Input file (default: read from stdin)',
        type=argparse.FileType('r'),
        default=sys.stdin
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file (default: write to stdout)',
        type=argparse.FileType('w'),
        default=sys.stdout
    )
    parser.add_argument(
        '--format', '-f',
        choices=['text', 'json', 'auto'],
        default='auto',
        help='Input format (default: auto-detect)'
    )
    parser.add_argument(
        '--pretty',
        action='store_true',
        help='Pretty-print JSON output'
    )

    args = parser.parse_args()

    # Read input
    content = args.input.read()

    # Auto-detect format if needed
    if args.format == 'auto':
        # Try to detect JSON
        content_stripped = content.strip()
        if content_stripped.startswith('{') or content_stripped.startswith('['):
            args.format = 'json'
        else:
            args.format = 'text'

    # Parse based on format
    if args.format == 'json':
        syscalls = parse_json_output(content)
    else:
        syscalls = parse_text_output(content)

    # Remove duplicates while preserving order
    seen = set()
    unique_syscalls = []
    for sc in syscalls:
        if sc not in seen:
            seen.add(sc)
            unique_syscalls.append(sc)

    # Create output JSON
    output_data = {
        "enable_syscalls": unique_syscalls
    }

    # Write output
    if args.pretty:
        json.dump(output_data, args.output, indent=2)
    else:
        json.dump(output_data, args.output)

    # Add newline if writing to stdout
    if args.output == sys.stdout:
        args.output.write('\n')

    # Print statistics to stderr
    print(f"Extracted {len(unique_syscalls)} unique syscalls", file=sys.stderr)


if __name__ == '__main__':
    main()
