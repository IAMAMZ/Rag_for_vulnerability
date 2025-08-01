#!/usr/bin/env python3
"""SEC-Bench Seed Generator.

This script processes CVE/OSV files and extracts relevant information
for security vulnerability benchmarking.

Features:
- Parse CVE/OSV files and extract relevant information
- Use rich progress bar for processing files
- Write results to JSONL file with progress tracking
- Display summary statistics
- Detect language of the repository
- Detect provider of the repository (GitHub or GitLab)
- Cache repository language information to avoid API calls

Usage:
    python seed.py --input_dir [CVE_OSV_DIR] --output_file [SEED_OUTPUT_FILE_PATH] --verbose

Options:
    --input-dir PATH       Directory containing CVE/OSV files
    --output-file PATH     Output file path (JSONL format)
    --log-file PATH        Log file path (default: logs/seed.log)
    --repo-lang-file PATH  Repository language mapping file
    --verbose, -v          Enable verbose logging

Output format:
    {
        "id": str,
        "details": str,
        "published": str,
        "references": list[str],
        "introduced": str,
        "fixed": str,
        "last_affected": str,
        "repo_url": str,
        "provider": str,
        "repo": str,
        "language": str,
    }
"""

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

# Import GitHub API client if available
try:
    from github import Github
    from github.GithubException import GithubException, RateLimitExceededException

    GITHUB_API_AVAILABLE = True
except ImportError:
    GITHUB_API_AVAILABLE = False
    logger.warning(
        "GitHub API client not available. Language detection will be limited."
    )

# Initialize rich console for display
console = Console()

# Global repository language cache
REPO_LANG_CACHE: Dict[str, str] = {}


def get_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Parse CVE/OSV files and extract relevant information"
    )
    parser.add_argument(
        "--input-dir", help="Directory containing input JSON files", required=True
    )
    parser.add_argument(
        "--output-file", help="Output file path (JSONL format)", required=True
    )
    parser.add_argument("--log-file", help="Log file path", default="logs/seed.log")
    parser.add_argument(
        "--repo-lang-file",
        help="Repository language mapping file (JSONL format)",
        default=get_default_repo_lang_path(),
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )
    return parser.parse_args()


def get_default_repo_lang_path() -> str:
    """Calculate the default repository language file path.

    Returns:
        Path to the default repository language mappings file.
    """
    # Get the directory of the current script
    script_dir = Path(os.path.dirname(os.path.abspath(__file__)))

    # Calculate the path to the data directory (sibling to collect)
    data_dir = script_dir.parent / "data"

    # Return the full path to the repository language mappings file
    return str(data_dir / "repository-language-mappings.jsonl")


def parse_repo_url(repo_url: str) -> Dict[str, str]:
    """Parse repository URL to extract provider, owner and repo name.

    Args:
        repo_url: URL of the repository.

    Returns:
        Dictionary with provider, owner and repo information.
    """
    if not repo_url:
        return {"provider": "", "owner": "", "repo": "", "full_name": ""}

    # Clean URL and remove .git suffix if present
    repo_url = repo_url.strip().rstrip("/")
    if repo_url.endswith(".git"):
        repo_url = repo_url[:-4]

    # Extract provider, owner and repo from URL
    github_pattern = r"https?://(?:www\.)?github\.com/([^/]+)/([^/]+)"
    gitlab_pattern = r"https?://(?:www\.)?gitlab\.com/([^/]+)/([^/]+)"

    github_match = re.match(github_pattern, repo_url)
    gitlab_match = re.match(gitlab_pattern, repo_url)

    if github_match:
        owner, repo = github_match.groups()
        return {
            "provider": "github",
            "owner": owner,
            "repo": repo,
            "full_name": f"{owner}/{repo}",
        }
    elif gitlab_match:
        owner, repo = gitlab_match.groups()
        return {
            "provider": "gitlab",
            "owner": owner,
            "repo": repo,
            "full_name": f"{owner}/{repo}",
        }
    else:
        # Try to handle non-standard URLs
        parts = repo_url.split("/")
        if len(parts) >= 2:
            # Take the last two parts as owner/repo
            owner = parts[-2]
            repo = parts[-1]

            # Try to determine provider
            provider = ""
            if "github" in repo_url.lower():
                provider = "github"
            elif "gitlab" in repo_url.lower():
                provider = "gitlab"

            return {
                "provider": provider,
                "owner": owner,
                "repo": repo,
                "full_name": f"{owner}/{repo}",
            }

    return {"provider": "", "owner": "", "repo": "", "full_name": ""}


def detect_github_language(repo_info: Dict[str, str]) -> Optional[str]:
    """Detect the main programming language of a GitHub repository.

    Args:
        repo_info: Dictionary with repository information.

    Returns:
        Main programming language or None if not found.
    """
    if not GITHUB_API_AVAILABLE:
        return None

    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        logger.warning(
            "No GITHUB_TOKEN environment variable found. "
            "Language detection may be rate limited."
        )

    try:
        g = Github(github_token) if github_token else Github()
        repo = g.get_repo(repo_info["full_name"])
        return repo.language
    except (GithubException, RateLimitExceededException) as e:
        logger.warning(f"Failed to detect language for {repo_info['full_name']}: {e}")
        return None
    except Exception as e:
        logger.warning(
            f"Unexpected error detecting language for {repo_info['full_name']}: {e}"
        )
        return None


def detect_gitlab_language(repo_info: Dict[str, str]) -> Optional[str]:
    """Detect the main programming language of a GitLab repository.

    Args:
        repo_info: Dictionary with repository information.

    Returns:
        Main programming language or None if not found.
    """
    # GitLab requires project ID which is different from the name
    # We'll need to search for the project first
    gitlab_token = os.getenv("GITLAB_TOKEN")

    if not gitlab_token:
        logger.warning(
            "No GITLAB_TOKEN environment variable found. GitLab API requires authentication."
        )
        return None

    # Set up headers with authentication token
    headers = {"PRIVATE-TOKEN": gitlab_token}

    try:
        # First, try to find the project by path with namespace (more precise)
        namespace_path = repo_info["full_name"]
        encoded_path = requests.utils.quote(namespace_path, safe="")
        project_url = f"https://gitlab.com/api/v4/projects/{encoded_path}"

        logger.debug(f"Querying GitLab API for project: {namespace_path}")
        response = requests.get(project_url, headers=headers)

        # If direct path lookup failed, try search
        if response.status_code == 404:
            logger.debug(
                f"Project not found by path, trying search: {repo_info['repo']}"
            )
            search_url = (
                f"https://gitlab.com/api/v4/projects?search={repo_info['repo']}"
            )
            response = requests.get(search_url, headers=headers)

            if response.status_code == 200:
                projects = response.json()
                project_id = None

                for project in projects:
                    # Try case-insensitive matching on path with namespace
                    if (
                        project.get("path_with_namespace", "").lower()
                        == repo_info["full_name"].lower()
                    ):
                        project_id = project["id"]
                        logger.debug(f"Found project ID via search: {project_id}")
                        break

                if not project_id:
                    logger.warning(
                        f"Could not find GitLab project ID for {repo_info['full_name']}"
                    )
                    return None
            else:
                if response.status_code == 401:
                    logger.error("GitLab API authentication failed (401 Unauthorized)")
                    logger.error(
                        "Please check your GITLAB_TOKEN is valid and has not expired"
                    )
                    return None
                else:
                    logger.warning(f"GitLab API error: {response.status_code}")
                    return None
        elif response.status_code == 200:
            # Direct path lookup successful
            project_data = response.json()
            project_id = project_data.get("id")
            logger.debug(f"Found project ID via direct path: {project_id}")
        elif response.status_code == 401:
            logger.error("GitLab API authentication failed (401 Unauthorized)")
            logger.error("Please check your GITLAB_TOKEN is valid and has not expired")
            return None
        else:
            logger.warning(f"GitLab API error: {response.status_code}")
            return None

        # Next, get the repository languages
        languages_url = f"https://gitlab.com/api/v4/projects/{project_id}/languages"
        logger.debug(f"Querying GitLab API for languages: {languages_url}")
        response = requests.get(languages_url, headers=headers)

        if response.status_code != 200:
            if response.status_code == 401:
                logger.error(
                    "GitLab API authentication failed (401 Unauthorized) when fetching languages"
                )
                return None
            else:
                logger.warning(
                    f"GitLab API error when fetching languages: {response.status_code}"
                )
                return None

        languages = response.json()
        if not languages:
            logger.info(
                f"No languages found for GitLab repository: {repo_info['full_name']}"
            )
            return None

        # Return the language with the highest percentage
        top_language = max(languages.items(), key=lambda x: x[1])[0]
        logger.info(
            f"Detected language for GitLab repository {repo_info['full_name']}: {top_language}"
        )
        return top_language

    except Exception as e:
        logger.error(
            f"Error detecting language for GitLab repository {repo_info['full_name']}: {e}"
        )
        return None


def load_repo_lang_cache(repo_lang_file: str) -> None:
    """Load repository language mapping from file into cache.

    Args:
        repo_lang_file: Path to repository language mapping file (JSONL).
    """
    global REPO_LANG_CACHE

    if not repo_lang_file or not os.path.exists(repo_lang_file):
        logger.info("No repository language file provided or file does not exist.")
        return

    try:
        with open(repo_lang_file, "r") as f:
            count = 0
            for line in f:
                try:
                    data = json.loads(line.strip())
                    if "repo_url" in data and "language" in data:
                        # Normalize URL (remove trailing slash and .git suffix)
                        repo_url = data["repo_url"].strip().rstrip("/")
                        if repo_url.endswith(".git"):
                            repo_url = repo_url[:-4]

                        REPO_LANG_CACHE[repo_url] = data["language"]
                        count += 1
                except json.JSONDecodeError:
                    logger.warning(
                        f"Failed to parse line in repository language file: {line[:50]}..."
                    )
                    continue

        logger.info(
            f"Loaded {count} repository language mappings from {repo_lang_file}"
        )
    except Exception as e:
        logger.error(f"Error loading repository language file: {e}")


def detect_repository_language(repo_url: str) -> Optional[str]:
    """Detect the main programming language of a repository.

    Args:
        repo_url: URL of the repository.

    Returns:
        Main programming language or None if not found.
    """
    if not repo_url:
        return None

    # Normalize URL
    normalized_url = repo_url.strip().rstrip("/")
    if normalized_url.endswith(".git"):
        normalized_url = normalized_url[:-4]

    # First check if we have the language in our cache
    if normalized_url in REPO_LANG_CACHE:
        logger.info(
            f"Found language for {repo_url} in cache: {REPO_LANG_CACHE[normalized_url]}"
        )
        return REPO_LANG_CACHE[normalized_url]

    # If not in cache, parse repository URL and try API-based detection
    repo_info = parse_repo_url(repo_url)
    if not repo_info["provider"]:
        logger.warning(f"Could not determine provider for repository URL: {repo_url}")
        return None

    # Detect language based on provider
    language = None
    if repo_info["provider"] == "github":
        language = detect_github_language(repo_info)
    elif repo_info["provider"] == "gitlab":
        language = detect_gitlab_language(repo_info)
    else:
        logger.warning(f"Unsupported repository provider: {repo_info['provider']}")
        return None

    # If detected, add to cache for future lookups
    if language:
        REPO_LANG_CACHE[normalized_url] = language

    return language


def parse_cve_osv_file(file_path: str) -> Dict[str, Any]:
    """Parse a CVE or OSV JSON file and extract relevant information.

    Args:
        file_path: Path to the JSON file.

    Returns:
        Dictionary containing extracted information.
    """
    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        result = {
            "id": data.get("id", ""),
            "details": data.get("details", ""),
            "published": data.get("published", ""),
            "references": [],
            "introduced": "",
            "fixed": "",
            "last_affected": "",
        }

        # Extract references
        if "references" in data:
            result["references"] = [ref.get("url", "") for ref in data["references"]]

        # Extract GitHub repo information
        if "affected" in data:
            for affected in data["affected"]:
                if "ranges" in affected:
                    for range_info in affected["ranges"]:
                        if range_info.get("type") == "GIT":
                            repo_url = range_info.get("repo", "")
                            result["repo_url"] = repo_url

                            # Parse repository URL to get provider and full repo name
                            repo_info = parse_repo_url(repo_url)
                            result["provider"] = repo_info["provider"]
                            result["repo"] = repo_info["full_name"].lower()

                            # Extract events if available
                            if "events" in range_info:
                                for event in range_info["events"]:
                                    if "introduced" in event:
                                        # Change "0" to empty string
                                        result["introduced"] = (
                                            ""
                                            if event["introduced"] == "0"
                                            else event["introduced"]
                                        )
                                    if "fixed" in event:
                                        # Change "0" to empty string
                                        result["fixed"] = (
                                            ""
                                            if event["fixed"] == "0"
                                            else event["fixed"]
                                        )
                                    if "last_affected" in event:
                                        # Change "0" to empty string
                                        result["last_affected"] = (
                                            ""
                                            if event["last_affected"] == "0"
                                            else event["last_affected"]
                                        )

                            # Detect repository language
                            if repo_url:
                                language = detect_repository_language(repo_url)
                                if language:
                                    result["language"] = language
                                    logger.info(
                                        f"Detected language for {repo_url}: {language}"
                                    )

                            # We found what we need, so break
                            break

        return result

    except Exception as e:
        logger.error(f"Error parsing {file_path}: {e}")
        return {}


def process_files(input_dir: str, output_file: str) -> None:
    """Process all JSON files in the input directory and save results to JSONL file.

    Args:
        input_dir: Directory containing input JSON files.
        output_file: Path to save the output JSONL file.
    """
    input_path = Path(input_dir)
    output_path = Path(output_file)

    # Display welcome message
    console.print(
        Panel.fit(
            "[bold blue]OSV Metadata Parser[/bold blue] - Extracting necessary information from OSV files",
            title="SEC-Bench",
        )
    )

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Find all JSON files in the input directory
    osv_files = list(input_path.glob("**/OSV-*.json"))
    cve_files = list(input_path.glob("**/CVE-*.json"))
    json_files = osv_files + cve_files

    console.print(
        f"Found [bold green]{len(osv_files)}[/bold green] OSV files and [bold green]{len(cve_files)}[/bold green] CVE files"
    )

    if not json_files:
        console.print(
            "[bold red]No CVE or OSV files found in the specified directory![/bold red]"
        )
        return

    # Initialize counters
    total_processed = 0
    languages_detected = 0

    # Open the output file in append mode
    with open(output_path, "w") as output_f:
        # Use rich progress bar for processing files
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
            # Create the main progress task
            main_task = progress.add_task(
                "[cyan]Processing files...", total=len(json_files)
            )

            # Process each file with progress tracking
            for file_path in json_files:
                progress.update(
                    main_task,
                    description=f"[cyan]Processing [bold]{file_path.name}[/bold]",
                )

                result = parse_cve_osv_file(str(file_path))
                if result:
                    # Check if all required fields are present and at least one version info is available
                    has_required_fields = (
                        result.get("provider")
                        and result.get("repo")
                        and result.get("language")
                    )

                    has_version_info = (
                        result.get("fixed")
                        or result.get("introduced")
                        or result.get("last_affected")
                    )

                    # Log processing status regardless of whether we save the result
                    log_msg = f"Processed {file_path.name}"
                    if "id" in result and result["id"]:
                        log_msg += f" (ID: {result['id']})"

                    if has_required_fields and has_version_info:
                        # All required fields are present and has version info, write to output file
                        output_f.write(json.dumps(result) + "\n")
                        output_f.flush()  # Ensure the data is written to disk
                        total_processed += 1
                        languages_detected += 1

                        log_msg += f", saved with provider: {result['provider']}, repo: {result['repo']}, language: {result['language']}"
                        if result.get("fixed"):
                            log_msg += f", fixed: {result['fixed']}"
                        if result.get("introduced"):
                            log_msg += f", introduced: {result['introduced']}"
                        if result.get("last_affected"):
                            log_msg += f", last_affected: {result['last_affected']}"
                    else:
                        # Missing required fields or version info, don't save
                        missing = []
                        if not result.get("provider"):
                            missing.append("provider")
                        if not result.get("repo"):
                            missing.append("repo")
                        if not result.get("language"):
                            missing.append("language")
                        if not has_version_info:
                            missing.append(
                                "version information (fixed/introduced/last_affected)"
                            )
                        log_msg += f", not saved (missing: {', '.join(missing)})"

                    logger.info(log_msg)
                else:
                    # Log failed processing attempts
                    logger.warning(f"Failed to process {file_path.name}")

                # Advance the progress bar
                progress.advance(main_task)

    # Display summary
    summary_text = (
        f"[bold green]Successfully processed {total_processed} files.[/bold green]\n"
    )
    summary_text += f"Detected programming languages for [bold cyan]{languages_detected}/{total_processed}[/bold cyan] repositories.\n"
    summary_text += f"Output saved to [bold blue]{output_path}[/bold blue]"

    console.print(Panel.fit(summary_text, title="Summary"))


def main() -> None:
    """Main function to run the script."""
    args = get_args()

    # Configure logger
    logger.remove()  # Remove default handler
    log_path = Path(args.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger.add(args.log_file, level="INFO" if not args.verbose else "DEBUG")
    logger.add(lambda msg: console.print(f"[dim]{msg}[/dim]") if args.verbose else None)

    # Display script header
    if not args.input_dir or not args.output_file:
        console.print(
            "[bold red]Error:[/bold red] Both --input_dir and --output_file are required"
        )
        return

    # Load repository language cache if file provided
    if args.repo_lang_file:
        load_repo_lang_cache(args.repo_lang_file)

    # Process the files
    try:
        process_files(
            args.input_dir,
            args.output_file,
        )
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Process interrupted by user[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        logger.exception("Unhandled exception")


if __name__ == "__main__":
    main()
