#!/usr/bin/env python3
"""
SEC-Bench Project Generator

This script processes vulnerability entries from a report.jsonl file and generates
project configurations for reproducing vulnerabilities using OSS-Fuzz projects.

It includes the following features:
- Fetching and processing vulnerability entries from a JSONL file
- Extracting repository and commit information
- Retrieving OSS-Fuzz project configurations for the relevant commits
- Generating modified Dockerfiles for reproducing vulnerabilities
- Tracking processed instances to prevent duplicated work
- Supporting incremental processing through append mode
- Rich progress reporting and logging

Usage:
    python project.py --input_file report.jsonl --output_file output/project.jsonl [options]

Options:
    --max-entries N       Limit processing to the first N entries
    --log-file PATH       Specify log file location (default: logs/project.log)
    --verbose, -v         Enable verbose logging
    --tracking-file PATH  Specify tracking file location (default: output/state_project.json)
    --force, -f           Force reprocessing of already processed entries
    --append, -a          Append to the output file instead of overwriting it
    --sanitizer-only      Only process entries with sanitizer error messages
    --minimal             Generate a minimalized Dockerfile and build script instead of using the original OSS-Fuzz files

Output format:
    {
        "instance_id": str,
        "repo": str,
        "base_commit": str,
        "date": datetime,
        "project_name": str,
        "lang": str,
        "dockerfile": str,
        "build_sh": str,
        "work_dir": str,
        "sanitizer": str,
        "bug_description": str,
        "additional_files": list[str],
        "candidate_fixes": list[str],
    }
"""

import base64
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import jinja2  # Add jinja2 import
import yaml  # type: ignore
from git import Repo
from github import Github
from loguru import logger
from rich.box import ROUNDED  # Import ROUNDED box style
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.prompt import Confirm

from secb.preprocessor.constants import (
    BASE_IMAGE_VERSIONS,
    BUILD_PATTERNS,
    COMMAND_EXCLUSION_OPTIONS,
    EXCLUDE_PATTERNS,
    FUZZER_LOOP_PATTERNS,
    PRIORITY_BUILD_COMMANDS,
)

# Initialize console for rich output
console = Console()

# Sanitizer error message patterns
SANITIZER_ERROR_PATTERNS = [
    "ERROR: AddressSanitizer:",
    "ERROR: MemorySanitizer:",
    "WARNING: MemorySanitizer:",
    "SUMMARY: UndefinedBehaviorSanitizer:",
    "UndefinedBehaviorSanitizer:DEADLYSIGNAL",
    "ERROR: LeakSanitizer:",
]


@dataclass
class ProcessResult:
    """Result of processing a vulnerability entry."""

    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def contains_sanitizer_error(bug_description: str) -> bool:
    """
    Check if a bug description contains sanitizer error messages.

    Args:
        bug_description: The bug description text

    Returns:
        True if the description contains any sanitizer error message, False otherwise
    """
    if not bug_description:
        return False

    for pattern in SANITIZER_ERROR_PATTERNS:
        if pattern in bug_description:
            return True

    return False


# Display a visual flowchart of the process
process_flowchart = """
┌───────────────┐     ┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│  1. Load Data │ ──> │  2. Filter    │ ──> │  3. Process   │ ──> │  4. Save      │
│  from JSONL   │     │  Projects     │     │  Entries      │     │  Results      │
└───────────────┘     └───────────────┘     └───────────────┘     └───────────────┘
                        ↑ for OSS-Fuzz       ↑ get configs         ↑ to JSONL
                        ↑ projects           ↑ modify Dockerfiles  ↑ track processed
                        ↑ check tracking     ↑ use GitHub API      ↑ entries
"""


def get_args():
    """Parse command line arguments."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate project configurations for reproducing vulnerabilities"
    )
    parser.add_argument(
        "--input-file",
        help="Input file path containing bug reports (report.jsonl)",
        required=True,
    )
    parser.add_argument(
        "--output-file",
        help="Output file path containing project information",
        required=True,
    )
    parser.add_argument(
        "--max-entries", type=int, help="Maximum number of entries to process"
    )
    parser.add_argument("--log-file", default="logs/project.log", help="Log file path")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "--tracking-file",
        help="Path to the tracking file for processed instances",
        default="output/state_project.json",
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force reprocessing of already processed entries",
    )
    parser.add_argument(
        "--append",
        "-a",
        action="store_true",
        help="Append to the output file instead of overwriting it",
    )
    parser.add_argument(
        "--sanitizer-only",
        action="store_true",
        help="Only process entries with sanitizer error messages",
    )
    parser.add_argument(
        "--minimal",
        action="store_true",
        help="Generate a minimalized Dockerfile and build script instead of using the original OSS-Fuzz files",
    )

    return parser.parse_args()


def parse_repo_url(repo_url: str) -> Tuple[str, str]:
    """
    Parse the repository URL into infrastructure and repository parts.

    Args:
        repo_url: URL of the repository, e.g., "https://github.com/unicode-org/icu.git"

    Returns:
        Tuple of (infra, repo), e.g., ("github.com", "unicode-org/icu")
    """
    # Remove potential leading/trailing whitespace and @ symbols
    repo_url = repo_url.strip().lstrip("@")

    # Use regex to extract the infrastructure and repository parts
    # Match both https:// and git:// URL formats
    pattern = r"(?:https?|git)://([^/]+)/(.+?)(?:\.git)?/?$"
    match = re.match(pattern, repo_url)

    if match:
        infra = match.group(1)
        repo = match.group(2)
        return infra, repo

    # Fallback for other formats or edge cases
    parts = repo_url.split("/")
    if len(parts) >= 3:
        # Handle URL format without protocol
        if "://" not in repo_url:
            infra = parts[0]
            repo = "/".join(parts[1:])
        else:
            infra = parts[2]
            repo = "/".join(parts[3:])

        # Remove .git suffix if present
        if repo.endswith(".git"):
            repo = repo[:-4]

        return infra, repo

    # Return original as fallback
    logger.warning(f"Could not parse repository URL: {repo_url}")
    return repo_url, repo_url


def get_oss_fuzz_project_list() -> List[str]:
    """
    Retrieve the list of projects from the 'projects' directory of the OSS-Fuzz repository.

    Returns:
        List of project names
    """
    try:
        temp_dir = Path("output/oss-fuzz")
        if not temp_dir.exists():
            logger.info("Cloning OSS-Fuzz repository...")
            Repo.clone_from("https://github.com/google/oss-fuzz.git", temp_dir, depth=1)

        # List all directories in the projects folder
        projects_dir = temp_dir / "projects"
        return [d.name for d in projects_dir.iterdir() if d.is_dir()]
    except Exception as e:
        logger.warning(
            f"Failed to clone repository: {e}, falling back to API with custom handling"
        )
        return []


def get_commit_parent(repo_str: str, commit_hash: str) -> Optional[str]:
    """
    Get the parent commit of the specified commit hash.

    Args:
        repo_str: Repository identifier (e.g., "unicode-org/icu")
        commit_hash: Commit hash whose parent we want to find

    Returns:
        Parent commit hash or None if not found
    """
    repo_dir = os.path.join("projects", repo_str.replace("/", "_"))
    if not os.path.exists(repo_dir):
        try:
            clone_url = f"https://github.com/{repo_str}"
            logger.info(f"Cloning repository {clone_url} to {repo_dir}...")
            Repo.clone_from(clone_url, repo_dir)
        except Exception as e:
            logger.error(f"Error cloning repository {repo_str}: {e}")
            return None

    try:
        repo = Repo(repo_dir)
        commit = repo.commit(commit_hash)
        if commit.parents:
            parent_hash = commit.parents[0].hexsha
            logger.info(f"Found parent commit {parent_hash} for {commit_hash}")
            return parent_hash
        else:
            logger.warning(
                f"Commit {commit_hash} has no parent (it might be the initial commit)"
            )
            return None
    except Exception as e:
        logger.error(
            f"Error retrieving parent commit for {commit_hash} in {repo_str}: {e}"
        )
        return None


def get_commit_datetime(repo_slug: str, commit_hash: str) -> Optional[datetime]:
    """
    Get commit datetime from a repository given a commit hash.

    Args:
        repo_slug: Repository identifier (e.g., "unicode-org/icu")
        commit_hash: Commit hash for which we want to find the datetime

    Returns:
        Datetime of the commit or None if not found
    """
    repo_dir = os.path.join("projects", repo_slug.replace("/", "_"))
    if not os.path.exists(repo_dir):
        try:
            clone_url = f"https://github.com/{repo_slug}"
            Repo.clone_from(clone_url, repo_dir)
        except Exception as e:
            logger.error(f"Error cloning repository {repo_slug}: {e}")
            return None

    try:
        repo = Repo(repo_dir)
        commit = repo.commit(commit_hash)
        return datetime.fromtimestamp(commit.committed_date)
    except Exception as e:
        logger.error(
            f"Error retrieving commit date for {commit_hash} in {repo_slug}: {e}"
        )
        return None


def get_oss_fuzz_files(
    project: str, commit_date: datetime
) -> Optional[Tuple[str, Dict[str, str]]]:
    """
    Get OSS-Fuzz project files from GitHub at the closest commit before commit_date.
    Uses caching to avoid re-downloading files.

    Args:
        project: Name of the OSS-Fuzz project
        commit_date: Target date to find closest commit before

    Returns:
        Tuple of (commit SHA, dict of filename->content) or None if failed
    """
    # Create cache directory if it doesn't exist
    cache_dir = Path("output/oss_fuzz_cache")
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Create project-specific cache directory
    project_cache_dir = cache_dir / project
    project_cache_dir.mkdir(exist_ok=True)

    # Create a cache key based on the date
    cache_key = commit_date.strftime("%Y%m%d")
    cache_file = project_cache_dir / f"{cache_key}.json"

    # Check if we have a cached version
    if cache_file.exists():
        try:
            with open(cache_file, "r") as f:
                cached_data = json.load(f)
                logger.info(
                    f"Using cached OSS-Fuzz files for {project} from {cache_key}"
                )
                return cached_data["commit"], cached_data["files"]
        except Exception as e:
            logger.warning(f"Error reading cache file {cache_file}: {e}")

    try:
        # Initialize GitHub client (use token if available)
        token = os.getenv("GITHUB_TOKEN")
        g = Github(token) if token else Github()

        # Get OSS-Fuzz repo
        repo = g.get_repo("google/oss-fuzz")

        # Get commits for the project directory before the target date.
        project_path = f"projects/{project}"

        commits = repo.get_commits(path=project_path, until=commit_date)
        if commits.totalCount:
            latest_commit = max(commits, key=lambda commit: commit.commit.author.date)
            logger.info(
                f"Found {commits.totalCount} commits for {project} until {commit_date}. Latest commit date: {latest_commit.commit.author.date}"
            )
            found_commit = latest_commit
        else:
            commits = repo.get_commits(path=project_path, since=commit_date)
            if commits.totalCount:
                oldest_commit = min(
                    commits, key=lambda commit: commit.commit.author.date
                )
                logger.info(
                    f"Found {commits.totalCount} commits for {project} since {commit_date}. Oldest commit date: {oldest_commit.commit.author.date}"
                )
                found_commit = oldest_commit
            else:
                logger.warning(
                    f"No OSS-Fuzz commits found for {project} around {commit_date}"
                )
                return None

        # Found a commit successfully
        closest_commit = found_commit
        logger.success(
            f"Found OSS-Fuzz commit {closest_commit.sha} from {closest_commit.commit.author.date}"
        )

        # Get all files in the project directory at this commit
        files = {}
        try:
            contents = repo.get_contents(project_path, ref=closest_commit.sha)
            # Convert single ContentFile to list if needed
            if not isinstance(contents, list):
                contents = [contents]

            for content in contents:
                if content.type == "file":
                    try:
                        # Decode content from base64
                        file_content = base64.b64decode(content.content).decode()
                        files[content.name] = file_content
                        logger.debug(f"Found file: {content.name}")
                    except Exception as e:
                        logger.warning(f"Could not decode {content.name}: {e}")
        except Exception as e:
            logger.error(f"Failed to get contents of {project_path}: {e}")
            return None

        # Verify we have the essential files
        essential_files = ["Dockerfile", "build.sh", "project.yaml"]
        missing_files = [f for f in essential_files if f not in files]
        if missing_files:
            logger.warning(f"Missing essential files: {', '.join(missing_files)}")

            # Try to get all essential files from the latest commit for consistency
            logger.info(
                f"Retrieving all essential files from latest commit for consistency"
            )
            try:
                latest_commits = repo.get_commits(path=project_path)
                if latest_commits.totalCount > 0:
                    latest_commit = latest_commits[0]
                    latest_contents = repo.get_contents(
                        project_path, ref=latest_commit.sha
                    )
                    if not isinstance(latest_contents, list):
                        latest_contents = [latest_contents]

                    for content in latest_contents:
                        if content.type == "file" and content.name in essential_files:
                            try:
                                file_content = base64.b64decode(
                                    content.content
                                ).decode()
                                files[content.name] = file_content
                                logger.info(
                                    f"Retrieved file {content.name} from latest commit"
                                )
                                if content.name in missing_files:
                                    missing_files.remove(content.name)
                            except Exception as e:
                                logger.warning(
                                    f"Could not decode {content.name} from latest commit: {e}"
                                )
            except Exception as e:
                logger.warning(f"Failed to retrieve files from latest commit: {e}")

            # Return None if we still have missing essential files
            if missing_files:
                logger.error(
                    f"Still missing essential files after fallback attempt: {', '.join(missing_files)}"
                )
                return None

        # Cache the results
        try:
            cache_data = {
                "commit": closest_commit.sha,
                "files": files,
                "date": commit_date.isoformat(),
                "cached_at": datetime.now().isoformat(),
            }
            with open(cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)
            logger.info(f"Cached OSS-Fuzz files for {project} from {cache_key}")
        except Exception as e:
            logger.warning(f"Failed to cache OSS-Fuzz files: {e}")

        return closest_commit.sha, files

    except Exception as e:
        logger.error(f"Failed to get OSS-Fuzz files: {e}")
        return None


def modify_dockerfile(
    dockerfile: str, repo_url: str, commit_hash: str, commit_date: datetime
) -> str:
    """
    Modify the Dockerfile to use the specified commit hash.

    Args:
        dockerfile: The original Dockerfile content
        repo_url: The repository URL
        commit_hash: The commit hash to check out
        commit_date: The date of the commit

    Returns:
        Modified Dockerfile content
    """
    lines = dockerfile.splitlines()

    logger.debug("Dockerfile (before):\n```dockerfile\n{}\n```", dockerfile)

    new_lines = []
    found_clone = False

    # Get the appropriate base image version for the commit date
    base_image = get_base_image_version(commit_date)

    for line in lines:
        # Replace the base image if this is the FROM line
        if line.strip().startswith("FROM"):
            # new_lines.append(f"FROM {base_image}")
            # NOTE: We use the latest base image for now
            new_lines.append("FROM hwiwonlee/secb.base:latest")
            continue

        # Skip existing checkout command if present
        if line.strip().startswith("RUN git -C"):
            continue

        # Use regex to match git clone commands and modify to use specific commit
        git_clone_pattern = rf"RUN\s+git\s+clone(?:\s+(?:--depth\s+1|--branch\s+\w+))*\s+{re.escape(repo_url)}(?:\.git)?(?=\s|$)(?:\s+(.+))?"
        match = re.search(git_clone_pattern, line)
        if match:
            # Use the captured directory name or extract from repo URL if not specified
            dest_dir = (
                match.group(1).strip() if match.group(1) else repo_url.split("/")[-1]
            )
            # Remove --depth 1 from the original clone command
            modified_clone_line = re.sub(r"\s+--depth\s+1", "", line)
            new_lines.append(modified_clone_line)
            new_lines.append(
                f"RUN git -C {dest_dir.replace('.git', '')} checkout {commit_hash}"
            )
            found_clone = True
        else:
            new_lines.append(line)

    # If we didn't find a clone command but found a checkout command,
    # just update the existing checkout command
    if not found_clone:
        # We need to find where the dest_dir might be defined
        dest_dir = None
        for i, line in enumerate(new_lines):
            if "git clone" in line and repo_url in line:
                # Try to extract the destination directory
                parts = line.split()
                if len(parts) > 4:  # RUN git clone URL DIR
                    dest_dir = parts[-1].replace(".git", "")
                else:
                    dest_dir = repo_url.split("/")[-1]
                break

        if dest_dir:
            for i, line in enumerate(new_lines):
                if line.strip().startswith("RUN git -C"):
                    new_lines[i] = f"RUN git -C {dest_dir} checkout {commit_hash}"
                    break
            else:
                # If no git -C command found, append one
                new_lines.append(f"RUN git -C {dest_dir} checkout {commit_hash}")

    new_dockerfile = "\n".join(new_lines)

    logger.debug("Dockerfile (after):\n```dockerfile\n{}\n```", new_dockerfile)

    return new_dockerfile


def minimize_build_script(build_sh: str) -> str:
    """
    Extract only the necessary project build commands from the OSS-Fuzz build script,
    filtering out fuzzer-specific commands.

    This function analyzes the original OSS-Fuzz build script and extracts only the
    commands needed to build the project itself, removing fuzzer-specific parts. It
    identifies common build patterns (configure, make, etc.) and excludes fuzzer-related
    commands (corpus generation, dictionary creation, etc.).

    The function also handles:
    - Function blocks and control structures (if/else/fi)
    - Common build system patterns across different languages
    - Preserves shebang line if present
    - Provides fallback commands if no build commands are found
    - Removes --enable-fuzzer option from configure commands
    - Adds -j$(nproc) to make commands for parallel builds
    - Handles multiline commands with backslash continuations, preserving indentation

    Args:
        build_sh: Original OSS-Fuzz build.sh content

    Returns:
        Minimized build script with only core build commands
    """
    # Extract the shebang if present
    shebang = ""
    lines = build_sh.splitlines()
    if lines and lines[0].startswith("#!"):
        shebang = lines[0]

    # Start with a header comment
    result = []
    if shebang:
        result.append(shebang)
    result.append("# Minimized build script with only core build commands")
    result.append("set -eu")

    # Preprocess to join multiline commands for analysis (but keep originals for output)
    joined_lines = []
    original_line_blocks = []
    current_block = []

    i = 0
    while i < len(lines):
        line = lines[i]

        # Skip comments and empty lines
        if not line.strip() or line.strip().startswith("#"):
            joined_lines.append(line)
            i += 1
            continue

        # Detect multiline command
        if line.strip().endswith("\\"):
            current_block = [line]
            joined_content = line.rstrip()[:-1] + " "  # Remove backslash

            # Collect all continuation lines
            i += 1
            while i < len(lines) and lines[i].strip().endswith("\\"):
                current_block.append(lines[i])
                joined_content += lines[i].strip()[:-1] + " "
                i += 1

            # Add final line if it exists
            if i < len(lines):
                current_block.append(lines[i])
                joined_content += lines[i].strip()
                i += 1

            # Store both the joined content and original lines
            joined_lines.append(joined_content)
            original_line_blocks.append(current_block)
        else:
            # Single line command
            joined_lines.append(line)
            i += 1

    # Track if we're in a function or if block section
    inside_block = False
    block_level = 0
    current_block_lines = []
    keep_current_block = False

    # Process each joined line
    i = 0
    make_found = False
    orig_block_idx = 0  # To track which original block we're on

    # First pass: identify fuzzer-specific patterns in the script
    # This helps to better identify fuzzer-related code blocks
    has_fuzzer_code = any(
        any(re.search(pattern, line) for pattern in EXCLUDE_PATTERNS)
        for line in joined_lines
    )

    # Additional patterns for fuzzer-specific for loops and commands

    while i < len(joined_lines):
        line = joined_lines[i].rstrip()

        # First, check if line contains any fuzzer-specific patterns directly
        # This is now done for ALL lines, not just in blocks
        has_exclude_pattern = any(
            re.search(exclude_pattern, line) for exclude_pattern in EXCLUDE_PATTERNS
        )

        # Also check against extended fuzzer loop patterns
        has_fuzzer_loop = any(
            re.search(pattern, line) for pattern in FUZZER_LOOP_PATTERNS
        )

        # Check if line is a priority build command - these should be kept regardless
        is_priority_command = any(
            re.search(pattern, line) for pattern in PRIORITY_BUILD_COMMANDS
        )

        # If the line is fuzzer-specific and NOT a priority command, skip it immediately
        if (has_exclude_pattern or has_fuzzer_loop) and not is_priority_command:
            i += 1
            continue

        # Handle block structures (functions, if/then/else/fi)
        if re.search(r"^\s*\w+\s*\(\)\s*{?\s*$", line) or line.strip().endswith(" {"):
            # Start of a function or block
            inside_block = True
            block_level = 1
            current_block_lines = [line]
            keep_current_block = any(
                re.search(pattern, line) for pattern in BUILD_PATTERNS
            )
            i += 1
            continue

        if inside_block:
            current_block_lines.append(line)

            # Update block level based on braces and if/fi
            if (
                line.strip() == "{"
                or line.strip().startswith("if ")
                or line.strip().startswith("for ")
            ):
                block_level += 1
            elif line.strip() == "}" or line.strip() == "fi" or line.strip() == "done":
                block_level -= 1

            # Check content of block to see if it contains build commands
            if not keep_current_block:
                keep_current_block = any(
                    re.search(pattern, line) for pattern in BUILD_PATTERNS
                )

            # Check if the block contains any fuzzer-specific commands
            # This is now checked for EVERY line in the block, not just at the end
            if not has_exclude_pattern:
                has_exclude_pattern = any(
                    re.search(exclude_pattern, line)
                    for exclude_pattern in EXCLUDE_PATTERNS
                )

            # Also check for fuzzer loops
            if not has_fuzzer_loop:
                has_fuzzer_loop = any(
                    re.search(pattern, line) for pattern in FUZZER_LOOP_PATTERNS
                )

            # Check if we've exited the block
            if block_level == 0:
                inside_block = False
                # Only include the block if it contains build commands and doesn't have fuzzer-specific patterns
                if (
                    keep_current_block
                    and not has_exclude_pattern
                    and not has_fuzzer_loop
                ):
                    result.extend(current_block_lines)
                current_block_lines = []
                keep_current_block = False

            i += 1
            continue

        # Skip empty lines or comments
        if not line or line.strip().startswith("#"):
            i += 1
            continue

        # Check if line contains build commands we want to keep
        should_keep = any(re.search(pattern, line) for pattern in BUILD_PATTERNS)

        # Special handling for commands with specific options to exclude (based on COMMAND_EXCLUSION_OPTIONS)
        command_pattern_match = None
        options_to_exclude = []
        for cmd_pattern, exclusion_options in COMMAND_EXCLUSION_OPTIONS.items():
            if re.search(cmd_pattern, line):
                command_pattern_match = cmd_pattern
                options_to_exclude = exclusion_options
                break

        # Check for options to exclude in the *joined* line first
        has_exclusion_option = False
        modified_line = line  # Start with the joined line
        if command_pattern_match:
            for option in options_to_exclude:
                # Check the modified_line (joined line) for the option
                if re.search(rf"(^|\s)({re.escape(option)})(\s|$|=)", modified_line):
                    has_exclusion_option = True
                    # Remove the option from the modified_line (this should be correct now)
                    modified_line = re.sub(
                        rf"(^|\s)({re.escape(option)})(\s|$|=)",  # Capture option as group 2
                        r"\1\3",  # Keep group 1 (before) and group 3 (after)
                        modified_line,
                    )
                    modified_line = re.sub(r"\s+", " ", modified_line).strip()

        if command_pattern_match and has_exclusion_option:
            # Check if this was originally a multiline command
            is_multiline = False
            original_lines = []
            # Find the corresponding original block
            for j, block in enumerate(original_line_blocks):
                joined_block_check = " ".join(
                    [l.strip().rstrip("\\").strip() for l in block]
                )
                # Simplified check: if the cleaned joined block contains the *modified* line content
                if modified_line in joined_block_check or line in joined_block_check:
                    is_multiline = True
                    original_lines = block
                    # Make sure we consume this block from original_line_blocks if needed
                    # orig_block_idx = j ? maybe needed if logic relies on index later
                    break

            if is_multiline:
                # For multiline commands, process the original lines individually
                new_lines = []
                for orig_line in original_lines:
                    new_line = orig_line
                    processed_line = new_line  # Start with the original line part
                    for option in options_to_exclude:
                        # Check this specific original line part for the option
                        if re.search(
                            rf"(^|\s)({re.escape(option)})(\s|$|=)", processed_line
                        ):
                            # Remove the option from this specific line part
                            processed_line = re.sub(
                                rf"(^|\s)({re.escape(option)})(\s|$|=)",  # Capture option as group 2
                                r"\1\3",  # Keep group 1 (before) and group 3 (after)
                                processed_line,
                            )
                            processed_line = re.sub(r"\s+", " ", processed_line).strip()

                        # Also handle edge cases like no space, end of line etc. on this specific line part
                        if command_pattern_match:
                            cmd_name = (
                                command_pattern_match.rstrip(r"\s")
                                .replace(r"\./", "./")
                                .replace(r"\s", "")
                            )
                            no_space_pattern = (
                                rf"({re.escape(cmd_name)})({re.escape(option)})"
                            )
                            if re.search(no_space_pattern, processed_line):
                                processed_line = re.sub(
                                    no_space_pattern, r"\1", processed_line
                                )

                        if processed_line.endswith(option):
                            processed_line = processed_line[: -len(option)].rstrip()

                        no_space_next_pattern = f"{option}--"
                        if no_space_next_pattern in processed_line:
                            processed_line = processed_line.replace(
                                no_space_next_pattern, "--"
                            )

                    # Only add the processed line if it's not empty or just a backslash
                    if processed_line.strip() not in ["\\", ""]:
                        new_lines.append(processed_line)

                # Ensure the last line doesn't end with a backslash
                if new_lines and new_lines[-1].strip().endswith("\\"):
                    new_lines[-1] = new_lines[-1].rstrip()[:-1].rstrip()

                result.extend(new_lines)
            else:
                # Handle single-line commands (or multiline that didn't need option removal per line)
                if len(modified_line) > 100:
                    # Format long single-line commands
                    cmd_parts = modified_line.split(None, 1)
                    base_cmd = cmd_parts[0]
                    options_list = (
                        cmd_parts[1].split() if len(cmd_parts) > 1 else []
                    )  # Renamed to avoid clash
                    indent = "        "
                    result.append(f"{base_cmd} \\")
                    for j, opt in enumerate(options_list):
                        result.append(
                            f"{indent}{opt}{' \\' if j < len(options_list) - 1 else ''}"
                        )
                else:
                    # Add the modified single line
                    result.append(modified_line)

            # Move to the next line in the main loop
            i += 1
            continue

        # For lines that aren't priority commands, and not already excluded due to fuzzer patterns:
        # Now we apply a stricter EXCLUDE_PATTERNS check before keeping the line
        if not is_priority_command:
            # Ignore lines matching exclusion patterns even if they match BUILD_PATTERNS
            if should_keep and not has_exclude_pattern and not has_fuzzer_loop:
                # Check if this is a multiline command in the original
                is_multiline = False
                for j, block in enumerate(original_line_blocks):
                    joined = " ".join([l.strip() for l in block])
                    if all(p in joined for p in line.split()) and len(line.split()) > 3:
                        is_multiline = True
                        result.extend(block)
                        orig_block_idx = j
                        break

                if not is_multiline:
                    result.append(line)

                # Mark if we found a make command
                if re.search(r"^make(\s|$)", line):
                    make_found = True
        else:
            # Priority commands are always kept regardless of fuzzer patterns
            # Check if this is a multiline command in the original
            is_multiline = False
            for j, block in enumerate(original_line_blocks):
                joined = " ".join([l.strip() for l in block])
                if all(p in joined for p in line.split()) and len(line.split()) > 3:
                    is_multiline = True
                    result.extend(block)
                    orig_block_idx = j
                    break

            if not is_multiline:
                result.append(line)

            # Mark if we found a make command
            if re.search(r"^make(\s|$)", line):
                make_found = True

        # Special handling for make commands - add -j$(nproc) for parallel builds if not present
        if (
            re.search(r"^make(\s|$)", line)
            and not re.search(r"-j\s*\$\(nproc\)", line)
            and not re.search(r"-j\s*[0-9]+", line)
        ):
            # Check if this is a multiline make command
            is_multiline = False
            original_lines = []

            # Look for the corresponding original block if this is a joined multiline
            for j, block in enumerate(original_line_blocks):
                joined = " ".join([l.strip() for l in block])
                if re.search(r"^make(\s|$)", joined) and all(
                    p in joined for p in line.split()
                ):
                    is_multiline = True
                    original_lines = block
                    orig_block_idx = j
                    break

            # Append -j$(nproc) for parallel builds
            if is_multiline:
                # For multiline make commands, preserve structure but add -j$(nproc) to the last line
                for j, orig_line in enumerate(original_lines):
                    if j < len(original_lines) - 1:
                        result.append(orig_line)
                    else:
                        # Add -j$(nproc) to the last line (remove trailing backslash if present)
                        last_line = orig_line.rstrip()
                        if last_line.endswith("\\"):
                            last_line = last_line[:-1].rstrip()
                        result.append(f"{last_line} -j$(nproc)")
            else:
                # Single line make command
                if line.strip() == "make":
                    modified_line = "make -j$(nproc)"
                else:
                    modified_line = f"{line.rstrip()} -j$(nproc)"

                # Check if this line needs to be added - it may have already been processed by the build patterns checks
                should_keep = any(
                    re.search(pattern, line) for pattern in BUILD_PATTERNS
                )
                is_priority_command = any(
                    re.search(pattern, line) for pattern in PRIORITY_BUILD_COMMANDS
                )
                # Only add if it hasn't already been added by the general build pattern matching
                if not should_keep and not is_priority_command:
                    result.append(modified_line)
                else:
                    # Replace the last added line with the modified one if it matches
                    if result and result[-1].strip() == line.strip():
                        result[-1] = modified_line

            make_found = True
            i += 1
            continue

        # Special handling for mkdir commands - add -p option if not present
        if (
            re.search(r"\bmkdir\b", line)
            and not re.search(r"\s-p\b", line)  # Check for -p option
            and not re.search(
                r"\s(--parents|--parent)\b", line
            )  # Check for --parents/--parent
            and not any(
                pat in line for pat in ["$format", "$OUT"]
            )  # Skip fuzzer-related mkdir
        ):
            # Check if this is a multiline mkdir command
            is_multiline = False
            original_lines = []

            # Look for the corresponding original block if this is a joined multiline
            for j, block in enumerate(original_line_blocks):
                joined = " ".join([l.strip() for l in block])
                if re.search(r"\bmkdir\b", joined) and all(
                    p in joined for p in line.split()
                ):
                    is_multiline = True
                    original_lines = block
                    orig_block_idx = j
                    break

            # Add -p option
            if is_multiline:
                # For multiline mkdir, find the line with mkdir and add -p
                modified_block = []
                added_p = False
                for orig_line in original_lines:
                    if re.search(r"\bmkdir\b", orig_line) and not added_p:
                        # Add -p after mkdir command
                        modified_line = re.sub(
                            r"(\bmkdir\b)", r"\1 -p", orig_line, count=1
                        )
                        modified_block.append(modified_line)
                        added_p = True
                    else:
                        modified_block.append(orig_line)
                result.extend(modified_block)
            else:
                # Single line mkdir command
                # Add -p after mkdir command
                modified_line = re.sub(r"(\bmkdir\b)", r"\1 -p", line, count=1)
                # Check if this line needs to be added - it may have already been processed by the build patterns checks
                should_keep = any(
                    re.search(pattern, line) for pattern in BUILD_PATTERNS
                )
                is_priority_command = any(
                    re.search(pattern, line) for pattern in PRIORITY_BUILD_COMMANDS
                )
                # Only add if it hasn't already been added by the general build pattern matching
                if not should_keep and not is_priority_command:
                    result.append(modified_line)
                else:
                    # Replace the last added line with the modified one if it matches
                    if result and result[-1].strip() == line.strip():
                        result[-1] = modified_line

            i += 1
            continue

        i += 1

    # Check for duplicates and remove them
    unique_results = []
    seen_lines = set()
    for line in result:
        stripped = line.strip()
        if stripped and stripped not in seen_lines and not stripped.startswith("#"):
            seen_lines.add(stripped)
            unique_results.append(line)
        elif stripped.startswith("#") or not stripped:
            unique_results.append(line)  # Always keep comments and empty lines

    # If we didn't find any build commands, add a comment explaining this
    if len(seen_lines) <= 2:  # Just the shebang, header, and set -eu
        logger.warning(f"len(seen_lines): {len(seen_lines)}")
        logger.warning(f"{seen_lines}")
        logger.info("Using the default build script template from build.sh.j2")
        template_path = Path(__file__).parent / "templates/build.sh.j2"

        try:
            with open(template_path, "r") as f:
                template_content = f.read()
            env = jinja2.Environment()
            template = env.from_string(template_content)

            # Render the template with default values
            # We can customize the config options based on project analysis
            config_opts = "--disable-shared"

            rendered_script = template.render(
                config_opts=config_opts,
                cmake_opts="-DCMAKE_BUILD_TYPE=Debug",
                make_opts="-j$(nproc)",
                build_dir="build",
            )
            return rendered_script
        except Exception as e:
            logger.error(f"Error rendering build script template: {e}")
            # Fall back to the simple approach if template rendering fails

    # If we have a successful build script but no make command was added, try to detect if we should add it
    elif not make_found and any(
        re.search(r"\.\/configure", line) for line in unique_results
    ):
        unique_results.append("make -j$(nproc)")

    return "\n".join(unique_results)


def parse_project_yaml(project_yaml_content: str) -> str:
    """
    Parse the project yaml file to extract language information.

    Args:
        project_yaml_content: Content of the project.yaml file

    Returns:
        Language extracted from the yaml file
    """
    yaml_dict = yaml.safe_load(project_yaml_content)

    lang = yaml_dict.get("language", "")

    # NOTE: Heuristic from ref.py
    if lang is None or lang.lower() == "unknown" or lang == "" or lang == "c":
        lang = "c++"

    return lang


def parse_work_dir(dockerfile_content: str) -> str:
    """
    Parse the work directory from the Dockerfile.

    Args:
        dockerfile_content: Content of the Dockerfile

    Returns:
        Work directory extracted from the Dockerfile
    """
    for line in dockerfile_content.splitlines():
        if "WORKDIR" in line:
            return (
                line.split("WORKDIR")[1]
                .strip()
                .replace("'", "")
                .replace("$SRC", "/src")
            )
    return ""


def extract_apt_install_commands(dockerfile_content: str) -> List[str]:
    """
    Extract APT package install commands from a Dockerfile.

    Args:
        dockerfile_content: Content of the Dockerfile

    Returns:
        List of apt package install commands found in the Dockerfile
    """
    apt_commands = []
    lines = dockerfile_content.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i].strip()

        # Check if this line contains an apt install command
        if ("apt-get" in line or "apt " in line) and (
            "install" in line or "update" in line
        ):
            # Start with the current line
            command_lines = [line]

            # If the line ends with a backslash, it continues to the next line
            while command_lines[-1].endswith("\\") and i + 1 < len(lines):
                i += 1
                # Keep the indentation for readability
                # Get the raw line to preserve indentation
                raw_line = lines[i]
                # Extract just the leading whitespace
                indent = len(raw_line) - len(raw_line.lstrip())
                if indent > 0:
                    # If there's indentation, preserve it
                    command_lines.append(raw_line)
                else:
                    # Otherwise, just use the stripped line
                    command_lines.append(raw_line.strip())

            # For a single line command, just add it
            if len(command_lines) == 1:
                apt_commands.append(command_lines[0])
            else:
                # For multi-line commands, fix the line continuations
                # The last line won't have a backslash
                for j in range(len(command_lines) - 1):
                    if command_lines[j].endswith("\\"):
                        # Keep the backslash if it already has one
                        pass
                    else:
                        # Add backslash if it doesn't have one
                        command_lines[j] = command_lines[j] + " \\"

                apt_commands.append("\n".join(command_lines))

        i += 1

    return apt_commands


def is_custom_apt_package_command(line: str) -> bool:
    """
    Check if a line contains a custom APT package command (e.g., ADD/COPY of .list files).

    Args:
        line: The Dockerfile line to check

    Returns:
        True if the line is a custom APT package command, False otherwise
    """
    # Pattern for ADD/COPY commands of .list files to apt sources
    pattern = r"^(?:ADD|COPY)\s+.*\.list\s+/etc/apt/sources\.list\.d/.*$"
    return bool(re.match(pattern, line.strip()))


def filter_apt_commands(dockerfile_lines: List[str]) -> List[str]:
    """
    Filter APT commands, excluding those that follow custom APT package commands.

    Args:
        dockerfile_lines: List of lines from the Dockerfile

    Returns:
        List of filtered APT commands
    """
    filtered_commands = []
    skip_next_apt = False

    for i, line in enumerate(dockerfile_lines):
        line = line.strip()

        # Check if this is a custom APT package command
        if is_custom_apt_package_command(line):
            skip_next_apt = True
            continue

        # Check if this is an APT command
        if ("apt-get" in line or "apt " in line) and (
            "install" in line or "update" in line
        ):
            if skip_next_apt:
                skip_next_apt = False  # Reset the flag
                continue

            # Start with the current line
            command_lines = [line]

            # If the line ends with a backslash, it continues to the next line
            j = i
            while j < len(dockerfile_lines) - 1 and dockerfile_lines[
                j
            ].strip().endswith("\\"):
                j += 1
                command_lines.append(dockerfile_lines[j].strip())

            # Join the command lines
            full_command = " ".join(line.rstrip("\\").strip() for line in command_lines)

            # Add RUN prefix if needed
            if not full_command.strip().startswith("RUN"):
                full_command = f"RUN {full_command}"

            filtered_commands.append(full_command)
        else:
            skip_next_apt = False  # Reset the flag for non-APT commands

    return filtered_commands


def generate_minimal_dockerfile(
    dockerfile: str,
    repo_url: str,
    base_commit: str,
    project_name: str,
    commit_date: datetime,
) -> str:
    """
    Generate a minimalized Dockerfile based on the collected Dockerfile.

    Args:
        dockerfile: The original Dockerfile content
        repo_url: The repository URL
        base_commit: The commit hash to check out
        project_name: The name of the project
        commit_date: The date of the commit

    Returns:
        Content of the minimalized Dockerfile

    Note:
        - There are some heuristics to remove unnecessary commands from the Dockerfile.
    """
    # Split dockerfile into lines for processing
    dockerfile_lines = dockerfile.splitlines()

    # Get filtered apt commands
    apt_commands = filter_apt_commands(dockerfile_lines)

    # Get the appropriate base image version for the commit date
    base_image = get_base_image_version(commit_date)

    # Create the minimalized Dockerfile
    # NOTE: We use the latest base image for now
    # minimal_dockerfile = [f"FROM {base_image}"]
    minimal_dockerfile = ["FROM hwiwonlee/secb.base:latest"]
    # Add apt commands if any were found
    minimal_dockerfile.extend(apt_commands)

    # Add git clone and checkout commands
    dest_dir = project_name
    minimal_dockerfile.append(f"RUN git clone {repo_url} {dest_dir}")
    minimal_dockerfile.append(f"RUN git -C {dest_dir} checkout {base_commit}")

    # Set working directory
    minimal_dockerfile.append(f"WORKDIR $SRC/{dest_dir}")

    # Copy build.sh
    minimal_dockerfile.append("COPY build.sh $SRC/")

    return "\n".join(minimal_dockerfile)


def get_base_image_version(commit_date: datetime) -> str:
    """
    Get the appropriate base image version based on the commit date.
    Uses the closest version that was available at or before the commit date.

    Args:
        commit_date: The date of the commit

    Returns:
        The appropriate base image version string
    """
    # Default to latest version if date is newer than all versions
    if commit_date > BASE_IMAGE_VERSIONS[0][0]:
        return BASE_IMAGE_VERSIONS[0][1]

    # Find the closest version before the commit date
    for version_date, image_version in BASE_IMAGE_VERSIONS:
        if commit_date >= version_date:
            logger.info(
                f"Using base image version from {version_date.strftime('%Y-%m')} for commit from {commit_date.strftime('%Y-%m-%d')}"
            )
            return image_version

    # If date is older than all versions, use the oldest version
    return BASE_IMAGE_VERSIONS[-1][1]


def correct_project_name_for_oss_fuzz(project_name: str) -> str:
    """
    Correct the project name for OSS-Fuzz.

    Some repositories have different names than their OSS-Fuzz project names.
    This function maps repository names to their corresponding OSS-Fuzz project names.

    Args:
        project_name: The original project name derived from the repository

    Returns:
        The corrected OSS-Fuzz project name
    """
    corrections = {
        "php-src": "php",
        "ox": "ox-ruby",
        "llama.cpp": "llamacpp",
        "ovs": "openvswitch",
        "libvncserver": "libvnc",
        "minizip-ng": "minizip",
        "libdwarf-code": "libdwarf",
        "little-cms": "lcms",
        "wasm-micro-runtime": "wamr",
        "core": "libreoffice",  # TODO: We may check whole project name like "https://git.libreoffice.org/core"
        "moddable": "xs",
    }

    return corrections.get(project_name, project_name)


def process_entry(
    entry: Dict[str, Any], oss_projects_set: set, minimal: bool = False
) -> ProcessResult:
    """
    Process a single vulnerability entry.

    Args:
        entry: The vulnerability entry from report.jsonl
        oss_projects_set: Set of OSS-Fuzz project names
        minimal: Whether to generate a minimalized Dockerfile

    Returns:
        ProcessResult containing either the processed entry or error information
    """
    # Extract repository URL
    repo_url = entry.get("repo_url", "")
    if not repo_url:
        return ProcessResult(
            success=False,
            error=f"Missing repo_url for entry {entry.get('id', 'unknown')}",
        )

    # Parse repository URL
    infra, repo_str = parse_repo_url(repo_url)
    if not repo_str or repo_str == repo_url:
        return ProcessResult(
            success=False,
            error=f"Unparseable repo_url for entry {entry.get('id', 'unknown')}: {repo_url}",
        )

    # Extract project name for OSS-Fuzz
    project_name = repo_str.split("/")[-1]
    # Apply the same correction
    corrected_name = correct_project_name_for_oss_fuzz(project_name)

    # Check if project is supported by OSS-Fuzz
    if corrected_name.lower() not in oss_projects_set:
        return ProcessResult(
            success=False, error=f"Project {repo_str} is not an OSS-Fuzz project"
        )

    # Determine base commit for vulnerability
    fixed_commit = entry.get("fixed")
    introduced_commit = entry.get("introduced")
    last_affected_commit = entry.get("last_affected")

    base_commit = None
    if fixed_commit:
        # Use the parent of the fix commit as the base commit
        base_commit = get_commit_parent(repo_str, fixed_commit)
    elif introduced_commit and introduced_commit != "0":
        # If no fix commit, use the introduced commit
        base_commit = introduced_commit
    elif last_affected_commit and last_affected_commit != "0":
        # If no fix commit, use the last affected commit
        base_commit = last_affected_commit
    else:
        return ProcessResult(
            success=False,
            error=f"Could not determine base commit for entry {entry.get('id', 'unknown')}",
        )

    # Check if base_commit is None before proceeding
    if base_commit is None:
        return ProcessResult(
            success=False,
            error=f"Base commit is None for entry {entry.get('id', 'unknown')}",
        )

    # Check if base_commit format is valid
    if len(base_commit) != 7 and len(base_commit) != 40:
        return ProcessResult(
            success=False,
            error=f"Incorrect format of base commit for entry {entry.get('id', 'unknown')}: {base_commit} in {repo_str}",
        )

    # Get the datetime of the commit for OSS-Fuzz file lookup
    commit_dt = get_commit_datetime(repo_str, base_commit)
    if commit_dt is None:
        return ProcessResult(
            success=False,
            error=f"Incorrect base commit for entry {entry.get('id', 'unknown')}: {base_commit} in {repo_str}",
        )

    # Retrieve OSS-Fuzz files
    build_sh = ""
    dockerfile = ""
    project_yaml = ""
    additional_files = []

    result = get_oss_fuzz_files(corrected_name, commit_dt)
    if result is None:
        return ProcessResult(
            success=False,
            error=f"Failed to retrieve OSS-Fuzz files for {corrected_name}",
        )

    files_dict = result[1]
    build_sh = files_dict.get("build.sh", "")
    dockerfile = files_dict.get("Dockerfile", "")
    project_yaml = files_dict.get("project.yaml", "")

    # Save additional files
    additional_files = [
        {"filename": fname, "content": content}
        for fname, content in files_dict.items()
        if fname not in ["Dockerfile", "build.sh", "project.yaml"]
    ]

    # Get full GitHub URL for the repository
    repo_url = f"https://github.com/{repo_str}"

    # Generate proper Dockerfile: either minimalized or modified
    if minimal:
        # Generate a minimalized Dockerfile
        modified_dockerfile = generate_minimal_dockerfile(
            dockerfile, repo_url, base_commit, project_name, commit_dt
        )
        logger.debug(
            "Generated minimal Dockerfile:\n```dockerfile\n{}\n```", modified_dockerfile
        )

        # Generate minimal build script if using minimal mode
        modified_build_sh = minimize_build_script(build_sh)
        logger.debug("Generated minimal build.sh:\n```bash\n{}\n```", modified_build_sh)
    else:
        # Modify Dockerfile for the specific commit
        modified_dockerfile = modify_dockerfile(
            dockerfile, repo_url, base_commit, commit_dt
        )

        # Use original build script
        modified_build_sh = build_sh

    # Extract language from project.yaml
    lang = parse_project_yaml(project_yaml)

    # Parse work directory from Dockerfile
    if minimal:
        # For minimal Dockerfiles, work directory is always $SRC/{project_name}
        work_dir = f"/src/{project_name}"
    else:
        work_dir = parse_work_dir(modified_dockerfile)
        if not work_dir:
            work_dir = os.path.join("/src", project_name)
        if not work_dir.startswith("/src"):
            work_dir = os.path.join("/src", work_dir)

    # Extract bug description if available
    bug_description = ""
    if "bug_descriptions" in entry and entry["bug_descriptions"]:
        descriptions = []
        total_descriptions = len(entry["bug_descriptions"])

        for idx, desc in enumerate(entry["bug_descriptions"], 1):
            desc_parts = []

            # Add report header with counter
            header = f"================= Bug Report ({idx}/{total_descriptions}) =================="
            desc_parts.append(header)

            # Add source information if available
            if "source" in desc:
                desc_parts.append(f"## Source: {desc['source']}")

            # Add URL information if available
            if "url" in desc:
                desc_parts.append(f"## URL: {desc['url']}")

            # Add the description text
            if "text" in desc:
                desc_parts.append(f"## Description:\n{desc['text']}")

            # Join all parts with newlines
            if desc_parts:
                descriptions.append("\n".join(desc_parts))

        # Join all descriptions with newlines
        bug_description = "\n\n".join(descriptions)

    # Create instance_id
    instance_id = f"{corrected_name}.{entry.get('id', '')}"

    # Determine the sanitizer from the bug description
    sanitizer = ""
    if "AddressSanitizer" in bug_description:
        sanitizer = "address"
    elif "UndefinedBehaviorSanitizer" in bug_description:
        sanitizer = "undefined"
    elif "MemorySanitizer" in bug_description:
        sanitizer = "memory"
    elif "ThreadSanitizer" in bug_description:
        sanitizer = "thread"
    elif "FuzzIntrospector" in bug_description:
        sanitizer = "introspector"
    elif "honggfuzz" in bug_description.lower():
        sanitizer = "honggfuzz"
    elif "afl" in bug_description.lower():
        sanitizer = "afl"
    elif entry.get("sanitizer"):
        entry_sanitizer = entry.get("sanitizer")
        if isinstance(entry_sanitizer, str):
            sanitizer = entry_sanitizer

    # Extract fixed commit from entry
    fixed_commits = entry.get("fixed_commits", [])

    # Prepare data for return
    output_obj = {
        "instance_id": instance_id.lower(),
        "repo": repo_str.lower(),
        "base_commit": base_commit,
        "date": commit_dt,
        "project_name": project_name,
        "lang": lang,
        "dockerfile": modified_dockerfile,
        "build_sh": modified_build_sh,
        "work_dir": work_dir,
        "sanitizer": sanitizer,
        "bug_description": bug_description,
        "additional_files": additional_files,
        "candidate_fixes": fixed_commits,
    }

    logger.info(
        "Successfully processed {} of {}@{}, date: {}, lang: {}, work_dir: {}",
        instance_id.lower(),
        project_name,
        base_commit,
        commit_dt.strftime("%Y-%m-%d"),
        lang,
        work_dir,
    )

    if minimal:
        logger.info("Generated minimal Dockerfile and build script")

    return ProcessResult(success=True, data=output_obj)


def load_processed_instances(tracking_file: Path) -> Dict[str, Dict[str, Any]]:
    """
    Load the dictionary of already processed instance IDs from the tracking file.

    Args:
        tracking_file: Path to the tracking file

    Returns:
        Dictionary of instance IDs that have already been processed and their metadata
    """
    if not tracking_file.exists():
        return {}

    try:
        with open(tracking_file, "r") as f:
            data = json.load(f)
            return data.get("processed_instances", {})
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error loading tracking file: {e}")
        return {}


def update_processed_instances(
    tracking_file: Path,
    instance_id: str,
    success: bool,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Update the tracking file with a new processed instance ID.

    Args:
        tracking_file: Path to the tracking file
        instance_id: The instance ID to add to the tracking file
        success: Whether the processing was successful
        metadata: Additional metadata to store about the instance
    """
    processed_instances = load_processed_instances(tracking_file)

    # Create or update instance data
    if metadata is None:
        metadata = {}

    processed_instances[instance_id] = {
        "timestamp": datetime.now().isoformat(),
        "success": success,
        **metadata,
    }

    try:
        tracking_file.parent.mkdir(parents=True, exist_ok=True)
        with open(tracking_file, "w") as f:
            json.dump({"processed_instances": processed_instances}, f, indent=2)
    except IOError as e:
        logger.error(f"Error updating tracking file: {e}")


# Custom JSON encoder to handle datetime objects
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def process_entries(
    input_file: str,
    output_file: str,
    max_entries: Optional[int] = None,
    tracking_file: Optional[str] = None,
    force_reprocess: bool = False,
    append_output: bool = False,
    sanitizer_only: bool = False,
    minimal: bool = False,
) -> None:
    """
    Process multiple vulnerability entries from an input file.

    Args:
        input_file: Path to the input file containing vulnerability entries
        output_file: Path to the output file for processed instances
        max_entries: Maximum number of entries to process (optional)
        tracking_file: Path to the tracking file (optional)
        force_reprocess: Whether to force reprocessing of already processed entries
        append_output: Whether to append to the output file instead of overwriting
        sanitizer_only: Whether to filter entries for those with sanitizer errors
        minimal: Whether to generate minimal Dockerfiles
    """
    # Make sure the input file exists
    input_path = Path(input_file)
    if not input_path.exists():
        console.print(f"[bold red]Input file not found: {input_file}[/bold red]")
        return

    # Create the output directory if it doesn't exist
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Setup tracking of processed instances
    tracking_path = (
        Path(tracking_file)
        if tracking_file
        else Path(output_file).with_suffix(".tracking.json")
    )
    processed_instances = {}
    if not force_reprocess:
        processed_instances = load_processed_instances(tracking_path)
        if processed_instances:
            console.print(
                f"[cyan]Found {len(processed_instances)} already processed instances[/cyan]"
            )

    # Display welcome message
    console.print(
        Panel.fit(
            "[bold blue]Generating project configurations[/bold blue] - Processing vulnerability entries",
            title="SEC-Bench",
        )
    )

    # Display a visual flowchart of the process
    console.print(
        Panel.fit(
            process_flowchart,
            title="Process Overview",
            border_style="blue",
            box=ROUNDED,
        )
    )

    # Get OSS-Fuzz project list once
    console.print("[cyan]Fetching OSS-Fuzz project list...[/cyan]")
    oss_projects = get_oss_fuzz_project_list()
    oss_projects_set = set([p.lower() for p in oss_projects])
    console.print(f"[green]Found {len(oss_projects)} OSS-Fuzz projects[/green]")

    # Check if output file exists and read existing instances
    existing_instances = {}
    if output_path.exists():
        try:
            with open(output_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        instance = json.loads(line)
                        if "instance_id" in instance:
                            existing_instances[instance["instance_id"]] = instance
                    except json.JSONDecodeError:
                        pass
            console.print(
                f"[cyan]Found {len(existing_instances)} existing instances in output file[/cyan]"
            )
        except IOError as e:
            logger.error(f"Error reading existing output file: {e}")

    # Read the input file and collect entries
    entries = []
    with open(input_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entries.append(entry)
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing JSON: {e}")

    # Apply sanitizer filter if requested
    if sanitizer_only:
        original_count = len(entries)
        filtered_entries = []

        console.print("[cyan]Filtering entries for sanitizer error messages...[/cyan]")

        for entry in entries:
            bug_descriptions = entry.get("bug_descriptions", [])
            descriptions_text = ""
            for desc in bug_descriptions:
                if "text" in desc:
                    descriptions_text += desc["text"] + "\n"

            if contains_sanitizer_error(descriptions_text):
                filtered_entries.append(entry)

        entries = filtered_entries
        console.print(
            f"[green]Filtered {original_count - len(entries)} entries without sanitizer errors. {len(entries)} entries remaining.[/green]"
        )

    # Apply max_entries limit if specified
    if max_entries is not None:
        entries = entries[:max_entries]

    console.print(f"Processing [bold cyan]{len(entries)}[/bold cyan] entries...")

    if minimal:
        console.print("[bold cyan]Using minimalized Dockerfile mode[/bold cyan]")

    # Ask for confirmation before proceeding
    user_input = Confirm.ask(
        f"Will you proceed with processing {len(entries)} entries?", default=True
    )
    if not user_input:
        console.print("[bold red]Operation cancelled by user.[/bold red]")
        return

    # Process entries with progress bar
    new_results = []
    skipped_count = 0
    error_count = 0
    timeout_count = 0
    TIMEOUT_SECONDS = 120  # 2 minutes timeout

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn(
            "[[bold green]{task.completed}[/bold green]/[bold yellow]{task.total}[/bold yellow]]"
        ),
        TaskProgressColumn(),
        TimeElapsedColumn(),
    ) as progress:
        extract_task = progress.add_task(
            "[cyan]Processing entries...", total=len(entries)
        )

        # Create a ThreadPoolExecutor for handling timeouts
        with ThreadPoolExecutor(max_workers=1) as executor:
            for entry in entries:
                bug_id = entry.get("id", "")
                repo = entry.get("repo", "")
                progress.update(
                    extract_task,
                    description=f"[cyan]Generating project configuration for [bold]{bug_id}[/bold] from [bold]{repo}[/bold]",
                )

                # Generate the instance_id for this entry to check if it's already processed
                repo_url = entry.get("repo_url", "")
                potential_instance_id = None

                if repo_url:
                    _, repo_str = parse_repo_url(repo_url)
                    project_name = repo_str.split("/")[-1]
                    corrected_name = project_name.replace("php-src", "php")
                    potential_instance_id = (
                        f"{corrected_name}.{entry.get('id', '')}".lower()
                    )

                    # Skip if already processed and we're not forcing reprocessing
                    if (
                        not force_reprocess
                        and potential_instance_id in processed_instances
                    ):
                        skipped_info = processed_instances[potential_instance_id]
                        if skipped_info.get("success", False):
                            logger.info(
                                f"Skipping already processed instance: {potential_instance_id}"
                            )
                            skipped_count += 1
                            progress.advance(extract_task)

                            # If the instance exists in the output file, include it in the new results
                            if (
                                append_output
                                and potential_instance_id in existing_instances
                            ):
                                new_results.append(
                                    existing_instances[potential_instance_id]
                                )
                            continue

                # Process the entry with timeout
                try:
                    future = executor.submit(
                        process_entry, entry, oss_projects_set, minimal
                    )
                    result = future.result(timeout=TIMEOUT_SECONDS)

                    if result.success and result.data:
                        new_results.append(result.data)
                        # Update tracking for successfully processed entries
                        if tracking_file or not force_reprocess:
                            metadata = {
                                "entry_id": entry.get("id", ""),
                                "repo_url": entry.get("repo_url", ""),
                                "fixed_commit": entry.get("fixed", ""),
                                "introduced_commit": entry.get("introduced", ""),
                                "last_affected_commit": entry.get("last_affected", ""),
                            }
                            update_processed_instances(
                                tracking_path,
                                result.data["instance_id"],
                                True,
                                metadata,
                            )
                    else:
                        # Record failed processing with detailed error message
                        error_count += 1
                        if potential_instance_id:
                            update_processed_instances(
                                tracking_path,
                                potential_instance_id,
                                False,
                                {
                                    "entry_id": entry.get("id", ""),
                                    "repo_url": entry.get("repo_url", ""),
                                    "error": result.error or "Unknown error",
                                },
                            )
                        logger.error(
                            f"Failed to process entry: {result.error or 'Unknown error'}"
                        )

                except TimeoutError:
                    timeout_count += 1
                    logger.warning(
                        f"Processing timed out after {TIMEOUT_SECONDS} seconds for entry {entry.get('id', 'unknown')}"
                    )
                    if potential_instance_id:
                        update_processed_instances(
                            tracking_path,
                            potential_instance_id,
                            False,
                            {
                                "entry_id": entry.get("id", ""),
                                "repo_url": entry.get("repo_url", ""),
                                "error": f"Processing timed out after {TIMEOUT_SECONDS} seconds",
                            },
                        )

                except Exception as e:
                    error_count += 1
                    logger.error(
                        f"Error processing entry {entry.get('id', 'unknown')}: {e}"
                    )
                    if potential_instance_id:
                        update_processed_instances(
                            tracking_path,
                            potential_instance_id,
                            False,
                            {
                                "entry_id": entry.get("id", ""),
                                "repo_url": entry.get("repo_url", ""),
                                "error": str(e),
                            },
                        )

                progress.advance(extract_task)

    # Write results to the output file
    output_mode = "a" if append_output else "w"
    with open(output_file, output_mode) as f:
        console.log(f"Writing {len(new_results)} results to {output_file}")
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            refresh_per_second=1,
        ) as progress:
            task = progress.add_task(
                "Writing to output file...", total=len(new_results)
            )

            for i, result in enumerate(new_results):
                # Use the custom encoder to handle datetime objects
                f.write(json.dumps(result, cls=DateTimeEncoder) + "\n")
                progress.update(task, advance=1)

    # Display summary
    summary_text = (
        f"[bold green]Finished processing {len(entries)} entries.[/bold green]\n"
    )

    # Calculate the number of newly generated results (not including existing ones)
    new_generated_count = len(
        [r for r in new_results if r["instance_id"] not in existing_instances]
    )
    summary_text += (
        f"Generated [bold cyan]{new_generated_count}[/bold cyan] new results.\n"
    )

    if skipped_count > 0:
        summary_text += f"Skipped [bold yellow]{skipped_count}[/bold yellow] already processed entries.\n"
    if error_count > 0:
        summary_text += f"Encountered [bold red]{error_count}[/bold red] errors during processing.\n"
    if timeout_count > 0:
        summary_text += f"[bold red]{timeout_count}[/bold red] entries timed out after {TIMEOUT_SECONDS} seconds.\n"

    if append_output:
        summary_text += f"Output appended to [bold blue]{output_file}[/bold blue]\n"
    else:
        summary_text += f"Output saved to [bold blue]{output_file}[/bold blue]\n"

    summary_text += (
        f"Tracking information saved to [bold blue]{tracking_path}[/bold blue]"
    )

    console.print(Panel.fit(summary_text, title="Summary"))


def main() -> None:
    """Main entry point for the script."""
    args = get_args()

    # Configure logger
    logger.remove()  # Remove default handler
    log_path = Path(args.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger.add(args.log_file, level="INFO" if not args.verbose else "DEBUG")
    logger.add(lambda msg: console.print(f"[dim]{msg}[/dim]") if args.verbose else None)

    # Process entries
    process_entries(
        args.input_file,
        args.output_file,
        args.max_entries,
        args.tracking_file,
        args.force,
        args.append,
        args.sanitizer_only,
        args.minimal,
    )


if __name__ == "__main__":
    main()
