#!/usr/bin/env python3
"""SEC-bench Repository Language Mapping Generator.

This module extracts repository language information from processed seed files
and generates a repository language mappings file. This allows caching of
repository language information to avoid redundant API calls to GitHub/GitLab.

Features:
- Extract language mappings from existing seed files
- Generate consolidated language mapping files
- Prevent duplicate entries with smart deduplication
- Support for appending to existing mapping files
- Structured JSONL output format with metadata
- Progress tracking and error handling

Usage:
    python generate_language_mappings.py --input-file <seed_file> [options]

Options:
    --input-file PATH     Input seed file path (JSONL format)
    --output-file PATH    Output repository language mapping file
    --append              Append to existing output file instead of overwriting

Output format:
    {
        "repo_url": str,    # Repository URL
        "provider": str,    # Git provider (github, gitlab)
        "repo": str,        # Repository full name (owner/repo)
        "language": str     # Primary programming language
    }
"""

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List, Set


# Get the default output path based on script location
def get_default_output_path() -> str:
    """Calculate the default output path relative to the script location."""
    # Get the directory of the current script
    script_dir = Path(os.path.dirname(os.path.abspath(__file__)))

    # Calculate the path to the data directory (sibling to collect)
    data_dir = script_dir.parent / "data"

    # Return the full path to the repository language mappings file
    return str(data_dir / "repository-language-mappings.jsonl")


def get_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract repository language information from seed file"
    )
    parser.add_argument(
        "--input-file", required=True, help="Input seed file path (JSONL format)"
    )
    parser.add_argument(
        "--output-file",
        default=get_default_output_path(),
        help="Output repository language mapping file path",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to existing output file instead of overwriting",
    )
    return parser.parse_args()


def extract_language_mappings(input_file: str) -> List[Dict[str, str]]:
    """Extract repository language mappings from seed file.

    Args:
        input_file: Path to input seed file

    Returns:
        List of repository language mapping entries
    """
    mappings = []

    try:
        with open(input_file, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    if all(
                        key in data
                        for key in ["repo_url", "provider", "repo", "language"]
                    ):
                        mapping = {
                            "repo_url": data["repo_url"],
                            "provider": data["provider"],
                            "repo": data["repo"],
                            "language": data["language"],
                        }
                        mappings.append(mapping)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"Error reading input file: {e}")
        return []

    return mappings


def save_language_mappings(
    mappings: List[Dict[str, str]], output_file: str, append: bool
) -> None:
    """Save repository language mappings to output file.

    Args:
        mappings: List of repository language mapping entries
        output_file: Path to output file
        append: Whether to append to existing file
    """
    mode = "a" if append else "w"
    unique_repos: Set[str] = set()

    # If appending, collect existing repo_urls to avoid duplicates
    if append and os.path.exists(output_file):
        try:
            with open(output_file, "r") as f:
                for line in f:
                    if line.startswith("#"):
                        continue
                    try:
                        data = json.loads(line.strip())
                        if "repo_url" in data:
                            unique_repos.add(data["repo_url"])
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error reading existing output file: {e}")

    # Ensure output directory exists
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write header if creating new file
    with open(output_file, mode) as f:
        if mode == "w":
            f.write("# Repository language mappings file for SEC-Bench\n")
            f.write(
                '# Format: {"repo_url": "https://github.com/owner/repo", "provider": "github", "repo": "owner/repo", "language": "Language"}\n'
            )
            f.write(
                "# This file is used to avoid making API calls to GitHub/GitLab for language detection\n"
            )

        # Write mappings, skipping duplicates
        new_entries = 0
        for mapping in mappings:
            if mapping["repo_url"] not in unique_repos:
                unique_repos.add(mapping["repo_url"])
                f.write(json.dumps(mapping) + "\n")
                new_entries += 1

    print(f"Saved {new_entries} new repository language mappings to {output_file}")
    if append:
        print(f"Total unique repositories in mapping file: {len(unique_repos)}")


def main():
    """Main function to run the script."""
    args = get_args()

    print(f"Extracting repository language mappings from {args.input_file}")
    mappings = extract_language_mappings(args.input_file)

    if not mappings:
        print("No repository language mappings found in the input file")
        return

    print(f"Found {len(mappings)} repository language mappings")
    save_language_mappings(mappings, args.output_file, args.append)


if __name__ == "__main__":
    main()
