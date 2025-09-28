#!/usr/bin/env python3
"""
Payload parser to extract all 'description' values from FIDO MDS3 payload.json
"""

import json
import sys
from pathlib import Path
from datetime import datetime


def extract_descriptions(obj, path=""):
    """
    Recursively extract all 'description' values from a JSON object.

    Args:
        obj: JSON object (dict, list, or primitive)
        path: Current path in the JSON structure for context

    Returns:
        List of tuples: (description_value, json_path)
    """
    descriptions = []

    if isinstance(obj, dict):
        for key, value in obj.items():
            current_path = f"{path}.{key}" if path else key

            # If this key is 'description', collect its value
            if key == 'description':
                descriptions.append((value, current_path))

            # Recursively search in the value
            descriptions.extend(extract_descriptions(value, current_path))

    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            current_path = f"{path}[{i}]"
            descriptions.extend(extract_descriptions(item, current_path))

    return descriptions


def write_descriptions_to_file(descriptions, output_dir="output"):
    """
    Write descriptions to a timestamped file.

    Args:
        descriptions: List of tuples (description_value, json_path)
        output_dir: Directory to write the file to

    Returns:
        Path to the created file
    """
    # Create output directory if it doesn't exist
    output_path = Path(__file__).parent / output_dir
    output_path.mkdir(exist_ok=True)

    # Generate timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"fido_descriptions_{timestamp}.txt"
    filepath = output_path / filename

    # Write descriptions to file
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("FIDO MDS3 Payload Descriptions\n")
        f.write("=" * 50 + "\n")
        f.write(f"Total descriptions found: {len(descriptions)}\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 50 + "\n\n")

        for i, (desc_value, json_path) in enumerate(descriptions, 1):
            f.write(f"{i:3}. Path: {json_path}\n")
            f.write(f"   Value: {desc_value}\n")
            f.write("\n")

    return filepath


def main():
    """Main function to parse payload.json and extract descriptions."""
    # Path to the payload.json file
    payload_path = Path(__file__).parent.parent / "fido-mds3" / "data" / "payload.json"

    if not payload_path.exists():
        print(f"Error: File not found: {payload_path}")
        sys.exit(1)

    try:
        print(f"Loading payload from: {payload_path}")
        print("This may take a moment for large files...\n")

        # Load the JSON file
        with open(payload_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        print(f"Successfully loaded JSON data")

        # Extract all descriptions
        descriptions = extract_descriptions(data)

        print(f"\nFound {len(descriptions)} description fields:")
        print("=" * 60)

        # Print each description with its path
        for i, (desc_value, json_path) in enumerate(descriptions, 1):
            print(f"{i:3}. Path: {json_path}")
            print(f"   Value: {desc_value}")
            print()

        # Write descriptions to timestamped file
        print("\nWriting descriptions to file...")
        output_file = write_descriptions_to_file(descriptions)
        print(f"Descriptions saved to: {output_file}")

    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {payload_path}")
        print(f"Details: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()