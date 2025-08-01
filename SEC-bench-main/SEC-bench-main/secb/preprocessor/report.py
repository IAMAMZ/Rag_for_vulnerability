#!/usr/bin/env python3
"""SEC-bench Bug Description Extractor.

This module processes vulnerability entries from seed files and extracts comprehensive
bug descriptions and fix commits from various reference URLs using web scraping
and API integration.

Features:
- Multi-platform bug report extraction (GitHub, Huntr.dev, OSS-Fuzz, Bugzilla, etc.)
- Selenium-based web scraping with intelligent selectors
- GitHub API integration for issues and security advisories
- Fix commit extraction from bug descriptions and URLs
- Intelligent caching to avoid redundant extractions
- Support for filtering by vulnerability type, language, and repository
- OSS-Fuzz project integration and filtering
- Rich progress reporting and comprehensive logging
- Multi-threaded processing for efficiency

Supported platforms:
- GitHub (issues, security advisories, pull requests)
- Huntr.dev vulnerability reports
- OSS-Fuzz bug tracker
- Mozilla Bugzilla instances
- PHP bug tracker
- Chromium bug tracker

Usage:
    python report.py --input-file <seed_file> --output-file <output_file> [options]

Options:
    --input-file PATH     Input seed file (JSONL format)
    --output-file PATH    Output file for extracted reports
    --reports-dir PATH    Directory to store cached bug reports
    --max-entries N       Limit processing to first N entries
    --type {CVE,OSV,ALL}  Filter by vulnerability type
    --lang LANGUAGES      Filter by programming languages (comma-separated)
    --blacklist REPOS     Exclude specified repositories (comma-separated)
    --whitelist REPOS     Include only specified repositories (comma-separated)
    --oss-fuzz [PATH]     Filter by OSS-Fuzz projects
    --fixed-only          Include only entries with fix commits
    --verbose, -v         Enable verbose logging

Output format:
    {
        "id": str,                                        # Vulnerability ID
        "details": str,                                   # Vulnerability details
        "published": str,                                 # Publication date
        "references": list[str],                          # Reference URLs
        "introduced": str,                                # Introduced commit
        "fixed": str,                                     # Original fixed commit
        "last_affected": str,                             # Last affected version
        "repo_url": str,                                  # Repository URL
        "provider": str,                                  # Git provider
        "repo": str,                                      # Repository name
        "language": str,                                  # Programming language
        "bug_descriptions": list[dict[str, str]],         # Extracted descriptions
        "fixed_commits": list[dict[str, Optional[str]]]   # Extracted fix commits
    }
"""

import argparse
import json
import os
import re
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

# HTML parsing imports
from bs4 import BeautifulSoup


# Add PHPComment class
class PHPComment:
    """Class to store PHP bug comments with metadata."""

    def __init__(self, author_info: str, text: str, links: List[str]):
        self.author_info = author_info
        self.text = text
        self.links = links


# GitHub API import
from github import Github
from github.GithubException import GithubException, RateLimitExceededException
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
)
from rich.prompt import Confirm
from rich.table import Table

# Selenium imports for bug report extraction
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

from secb.preprocessor.constants import OSV_MAPPING

# Initialize rich console for display
console = Console()

# Display a visual flowchart of the process
process_flowchart = """
┌───────────────┐     ┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│  1. Load Data │ ──> │  2. Filter    │ ──> │  3. Extract   │ ──> │  4. Save      │
│  from JSONL   │     │  Entries      │     │  Descriptions │     │  Results      │
└───────────────┘     └───────────────┘     └───────────────┘     └───────────────┘
                        ↑ by type            ↑ from references     ↑ to JSONL
                        ↑ by language        ↑ using Selenium      ↑ and disk cache
                        ↑ by repo name       ↑ and GitHub API
"""


def extract_github_attachments(text: str) -> List[str]:
    """Extract attachment URLs from GitHub markdown text or HTML content"""
    return re.findall(
        r"\[.*?\]\((https://github\.com/.*?/files/.*?)\)",
        text,
    )


def generate_default_github_url(repo_owner: str, repo_name: str, sha: str) -> str:
    """
    Generate a default GitHub URL for a commit hash.

    Args:
        repo_owner: GitHub repository owner
        repo_name: GitHub repository name
        sha: Commit hash

    Returns:
        str: GitHub URL for the commit
    """
    return f"https://github.com/{repo_owner}/{repo_name}/commit/{sha}"


def extract_fix_commits(
    text: str, repo_owner: Optional[str] = None, repo_name: Optional[str] = None
) -> List[Dict[str, Optional[str]]]:
    """
    Extract potential fix commits (SHA and URL) from bug descriptions using regex patterns.

    Args:
        text: The bug description text to analyze
        repo_owner: Optional GitHub repository owner to use for default URLs
        repo_name: Optional GitHub repository name to use for default URLs

    Returns:
        List[Dict[str, Optional[str]]]: List of unique potential fix commit dictionaries ({"sha": str, "url": Optional[str]})
    """
    fix_commits_dict: Dict[str, Dict[str, Optional[str]]] = {}

    # Extract GitHub/GitLab/Bitbucket commit URLs first (prioritize getting the URL)
    # Combined pattern for major platforms
    commit_url_pattern = r"(https?://(?:github\.com|gitlab\.(?:com|org)|bitbucket\.org)/[^/]+/[^/]+/(?:commit|commits|-/commit)/([0-9a-f]{7,40}))"
    for url, sha in re.findall(commit_url_pattern, text):
        # Always update with the URL if found
        fix_commits_dict[sha] = {"sha": sha, "url": url}

    # Extract full 40-char commit SHAs (only add if not already found with a URL)
    sha_pattern = r"\b([0-9a-f]{40})\b"
    for sha in re.findall(sha_pattern, text):
        if sha not in fix_commits_dict:
            default_url = None
            if repo_owner and repo_name:
                default_url = generate_default_github_url(repo_owner, repo_name, sha)
            fix_commits_dict[sha] = {"sha": sha, "url": default_url}

    # Extract short SHAs if they appear in fix-related contexts
    fix_context_patterns = [
        r"(?i)fix(?:ed|ing)?\s+(?:in|by|with)?\s+commit\s+\b([0-9a-f]{7,40})\b",
        r"(?i)patch(?:ed)?\s+(?:in|by|with)?\s+commit\s+\b([0-9a-f]{7,40})\b",
        r"(?i)fix\s+commit\s*:?\s*\b([0-9a-f]{7,40})\b",
        r"(?i)fixing\s+commit\s*:?\s*\b([0-9a-f]{7,40})\b",  # Added colon optional
        r"(?i)fixed\s+(?:in|by)\s*:?\s*\b([0-9a-f]{7,40})\b",
        r"(?i)the\s+fix\s+is\s+in\s+\b([0-9a-f]{7,40})\b",
    ]

    for pattern in fix_context_patterns:
        for sha in re.findall(pattern, text):
            # Only add if it's a valid SHA format and not already present
            if (
                re.match(r"^[0-9a-f]+$", sha)
                and len(sha) >= 7
                and sha not in fix_commits_dict
            ):
                default_url = None
                if repo_owner and repo_name:
                    default_url = generate_default_github_url(
                        repo_owner, repo_name, sha
                    )
                fix_commits_dict[sha] = {"sha": sha, "url": default_url}

    # PR patterns remain for potential future use, but don't extract commit info from them here
    # pr_patterns = [ ... ]

    return list(fix_commits_dict.values())


def is_fix_related(text: str) -> bool:
    """
    Check if text contains vulnerability fix-related keywords.

    Args:
        text: The text to check

    Returns:
        bool: True if the text contains fix-related keywords, False otherwise
    """
    if not text:
        return False
    return bool(
        re.search(
            r"(?i)fix|patch|resolve|close|leak|overflow|dereference|crash|segfault|vulnerability|security|issue|cve-",
            text,
        )
    )


def process_github_issue(
    issue,
    repo,
    fix_commits_dict: Dict[str, Dict[str, Optional[str]]],
    processed_issues=None,
    processed_prs=None,
):
    """
    Process a GitHub issue to extract fix commits, handling both the issue itself and its timeline events.

    Args:
        issue: GitHub issue object
        repo: GitHub repository object
        fix_commits_dict: Dictionary to store found fix commits (keyed by SHA)
        processed_issues: Set of already processed issue numbers to prevent infinite recursion
        processed_prs: Set of already processed PR numbers
    """
    if processed_issues is None:
        processed_issues = set()
    if processed_prs is None:
        processed_prs = set()

    # Get issue number and check if already processed
    issue_number = issue.number
    if issue_number in processed_issues:
        logger.debug(f"Skipping already processed issue #{issue_number}")
        return

    processed_issues.add(issue_number)
    logger.info(f"Processing issue #{issue_number}")

    # Extract commits from issue body
    if issue.body:
        body_commits = extract_fix_commits(issue.body)
        # Merge body_commits into fix_commits_dict
        for commit_info in body_commits:
            sha = commit_info.get("sha")
            if sha and (sha not in fix_commits_dict or commit_info.get("url")):
                fix_commits_dict[sha] = commit_info
        logger.debug(f"Found {len(body_commits)} commits in issue body")

    # Process comments for commits and references
    reference_numbers = []
    for comment in issue.get_comments():
        if comment.body:
            # Extract commits from comment
            comment_commits = extract_fix_commits(comment.body)
            # Merge comment_commits into fix_commits_dict
            for commit_info in comment_commits:
                sha = commit_info.get("sha")
                if sha and (sha not in fix_commits_dict or commit_info.get("url")):
                    fix_commits_dict[sha] = commit_info
            logger.debug(f"Found {len(comment_commits)} commits in comment")

            # Extract PR and issue references
            ref_matches = re.findall(r"(?:#|pull/|pulls/|issues/)(\d+)", comment.body)
            reference_numbers.extend(
                [num for num in ref_matches if num != str(issue_number)]
            )

    # Process timeline events
    logger.info(f"Examining timeline events for issue #{issue_number}")
    for event in issue.get_timeline():
        # Handle referenced commits
        commit_id = None
        commit_url = None  # Store URL alongside ID
        if hasattr(event, "commit_id") and event.commit_id:
            commit_id = event.commit_id
            commit_url = getattr(event, "commit_url", None)
            # Standardize GitHub API URL if needed
            if commit_url and "api.github.com" in commit_url:
                commit_url = commit_url.replace(
                    "api.github.com/repos", "github.com"
                ).replace("/commits/", "/commit/")
        elif hasattr(event, "sha") and event.sha:
            commit_id = event.sha
            commit_url = getattr(event, "html_url", None)

        if commit_id:
            try:
                commit = repo.get_commit(commit_id)
                if not commit_url:  # Fallback to commit object URL
                    commit_url = commit.html_url

                if is_fix_related(commit.commit.message):
                    logger.info(f"Found fix commit in timeline: {commit_id}")
                    # Update dict, prioritizing URL
                    if commit_id not in fix_commits_dict or commit_url:
                        fix_commits_dict[commit_id] = {
                            "sha": commit_id,
                            "url": commit_url,
                        }
                else:
                    logger.debug(
                        f"Skipping commit {commit_id} - no fix-related keywords in message"
                    )
            except Exception as e:
                logger.warning(f"Error checking commit {commit_id}: {e}")

        # Handle cross-referenced items
        elif hasattr(event, "event") and event.event == "cross-referenced":
            if hasattr(event, "source") and event.source:
                # Handle cross-referenced commits
                if hasattr(event.source, "type") and event.source.type == "commit":
                    commit_id = getattr(event.source, "id", None) or getattr(
                        event.source, "sha", None
                    )
                    if commit_id:
                        try:
                            commit = repo.get_commit(commit_id)
                            if not commit_url:  # Fallback to commit object URL
                                commit_url = commit.html_url

                            if is_fix_related(commit.commit.message):
                                logger.info(
                                    f"Found cross-referenced fix commit: {commit_id}"
                                )
                                # Update dict, prioritizing URL
                                if commit_id not in fix_commits_dict or commit_url:
                                    fix_commits_dict[commit_id] = {
                                        "sha": commit_id,
                                        "url": commit_url,
                                    }
                            else:
                                logger.debug(
                                    f"Skipping commit {commit_id} - no fix-related keywords in message"
                                )
                        except Exception as e:
                            logger.warning(f"Error checking commit {commit_id}: {e}")
                            # Add even if check failed, if not already present
                            fix_commits_dict[commit_id] = {
                                "sha": commit_id,
                                "url": commit_url,
                            }

                # Handle cross-referenced issues and PRs
                elif hasattr(event.source, "issue"):
                    ref_number = event.source.issue.number
                    reference_numbers.append(str(ref_number))

    # Process collected reference numbers
    for ref_number in set(reference_numbers):
        try:
            # Try as PR first
            try:
                pr = repo.get_pull(int(ref_number))
                if ref_number not in processed_prs:
                    processed_prs.add(ref_number)
                    if is_fix_related(pr.title) or (
                        pr.body and is_fix_related(pr.body)
                    ):
                        logger.info(f"Processing fix-related PR #{ref_number}")
                        for commit in pr.get_commits():
                            commit_sha = commit.sha
                            commit_url = commit.html_url  # Get URL from commit object
                            if is_fix_related(commit.commit.message):
                                # Update dict, prioritizing URL
                                if commit_sha not in fix_commits_dict or commit_url:
                                    fix_commits_dict[commit_sha] = {
                                        "sha": commit_sha,
                                        "url": commit_url,
                                    }
                                logger.info(
                                    f"Added fix commit {commit.sha} from PR #{ref_number}"
                                )
            except GithubException as pr_error:
                if pr_error.status == 404:
                    # Try as issue if not a PR
                    try:
                        referenced_issue = repo.get_issue(int(ref_number))
                        if referenced_issue.number not in processed_issues:
                            if is_fix_related(referenced_issue.title):
                                process_github_issue(
                                    referenced_issue,
                                    repo,
                                    fix_commits_dict,  # Pass the correct dict
                                    processed_issues,
                                    processed_prs,
                                )
                    except GithubException:
                        logger.debug(f"Reference #{ref_number} not found as issue")
                else:
                    logger.warning(f"Error processing PR #{ref_number}: {pr_error}")
        except Exception as e:
            logger.warning(f"Error processing reference #{ref_number}: {e}")


def extract_fix_commits_from_github_issue(url: str) -> List[Dict[str, Optional[str]]]:
    """
    Extract fix commits (SHA and URL) specifically from GitHub issues using GitHub API.

    Args:
        url: GitHub issue URL

    Returns:
        List[Dict[str, Optional[str]]]: List of extracted fix commit dictionaries
    """
    fix_commits_dict: Dict[str, Dict[str, Optional[str]]] = {}
    github_token = os.getenv("GITHUB_TOKEN")

    if not github_token:
        logger.warning("No GITHUB_TOKEN found for GitHub API access")
        return []

    # Extract repo owner, name, and issue number
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)/issues/(\d+)", url)
    if not match:
        logger.warning(f"Could not parse GitHub issue URL: {url}")
        return []

    owner, repo_name, issue_id = match.groups()

    try:
        # Initialize GitHub API
        g = Github(github_token)
        repo = g.get_repo(f"{owner}/{repo_name}")
        issue = repo.get_issue(int(issue_id))

        # Process the main issue and all its references
        process_github_issue(issue, repo, fix_commits_dict)

    except Exception as e:
        logger.error(f"GitHub API error extracting fix commits: {e}")

    return list(fix_commits_dict.values())


def extract_fix_commits_from_github_advisory(
    url: str,
) -> List[Dict[str, Optional[str]]]:
    """
    Extract fix commits (SHA and URL) from GitHub security advisories using GitHub API.

    Args:
        url: GitHub security advisory URL

    Returns:
        List[Dict[str, Optional[str]]]: List of extracted fix commit dictionaries
    """
    fix_commits_dict: Dict[str, Dict[str, Optional[str]]] = {}
    github_token = os.getenv("GITHUB_TOKEN")

    if not github_token:
        logger.warning("No GITHUB_TOKEN found for GitHub API access")
        return []

    # Extract GHSA ID
    advisory_id_match = re.search(r"/(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", url)
    if not advisory_id_match:
        logger.warning(f"Could not parse GitHub advisory URL: {url}")
        return []

    ghsa_id = advisory_id_match.group(1)

    try:
        # Initialize GitHub API
        g = Github(github_token)
        advisory = g.get_global_advisory(ghsa_id)

        # Extract commits from references
        if hasattr(advisory, "references") and advisory.references:
            for reference in advisory.references:
                # Look for commit URLs in references
                commit_info = extract_commit_from_url(reference)
                if commit_info:
                    sha = commit_info.get("sha")
                    # Store with URL from reference
                    if sha:
                        fix_commits_dict[sha] = commit_info

        # Extract commits mentioned in the description
        if advisory.description:
            description_commits = extract_fix_commits(advisory.description)
            for commit_info in description_commits:
                sha = commit_info.get("sha")
                # Add if not present, or update if the new entry has a URL
                if sha and (sha not in fix_commits_dict or commit_info.get("url")):
                    fix_commits_dict[sha] = commit_info

    except Exception as e:
        logger.error(f"GitHub API error extracting fix commits from advisory: {e}")

    return list(fix_commits_dict.values())


def extract_fix_commits_from_github_pr(url: str) -> List[Dict[str, Optional[str]]]:
    """
    Extract fix commits from a GitHub pull request.

    Args:
        url: GitHub PR URL

    Returns:
        List[str]: List of extracted fix commit SHAs
    """
    fix_commits_dict: Dict[str, Dict[str, Optional[str]]] = {}
    github_token = os.getenv("GITHUB_TOKEN")

    if not github_token:
        logger.warning("No GITHUB_TOKEN found for GitHub API access")
        return []

    # Extract repo owner, name, and PR number
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)", url)
    if not match:
        logger.warning(f"Could not parse GitHub PR URL: {url}")
        return []

    owner, repo_name, pr_number = match.groups()

    try:
        # Initialize GitHub API
        g = Github(github_token)
        repo = g.get_repo(f"{owner}/{repo_name}")
        pr = repo.get_pull(int(pr_number))

        # Check if PR is fix-related
        if is_fix_related(pr.title) or (pr.body and is_fix_related(pr.body)):
            logger.info(f"Processing fix-related PR #{pr_number}")
            # Get commits from this PR
            for commit in pr.get_commits():
                if is_fix_related(commit.commit.message):
                    commit_sha = commit.sha
                    commit_url = commit.html_url
                    fix_commits_dict[commit_sha] = {
                        "sha": commit_sha,
                        "url": commit_url,
                    }
                    logger.info(f"Added fix commit {commit.sha} from PR #{pr_number}")

    except Exception as e:
        logger.error(f"GitHub API error extracting fix commits from PR: {e}")

    return list(fix_commits_dict.values())


def extract_fix_commits_from_huntr(
    url: str, bug_description: Optional[str] = None
) -> List[Dict[str, Optional[str]]]:
    """
    Extract fix commits (SHA and URL) from Huntr.dev bounty reports.

    Args:
        url: Huntr.dev bounty URL
        bug_description: Optional pre-extracted bug description text

    Returns:
        List[Dict[str, Optional[str]]]: List of extracted fix commit dictionaries
    """
    fix_commits_dict: Dict[str, Dict[str, Optional[str]]] = {}

    # If we already have the bug description, extract from it
    if bug_description:
        # First extract direct commit references from text
        text_commits = extract_fix_commits(bug_description)
        for commit_info in text_commits:
            # Prioritize URLs from text if already present
            sha = commit_info.get("sha")
            if sha and (sha not in fix_commits_dict or commit_info.get("url")):
                fix_commits_dict[sha] = commit_info

        # Then look for GitHub issue/PR references in the description
        github_urls = re.findall(
            r"https://github\.com/[^/]+/[^/]+/(?:issues|pull)/\d+", bug_description
        )

        for github_url in github_urls:
            try:
                extracted_commits = []
                if "/pull/" in github_url:
                    extracted_commits = extract_fix_commits_from_github_pr(github_url)
                else:
                    extracted_commits = extract_fix_commits_from_github_issue(
                        github_url
                    )

                for commit_info in extracted_commits:
                    sha = commit_info.get("sha")
                    # Prioritize entries with URLs from GitHub API
                    if sha and (sha not in fix_commits_dict or commit_info.get("url")):
                        fix_commits_dict[sha] = commit_info
            except Exception as e:
                logger.warning(
                    f"Error processing GitHub URL {github_url} from bug description: {e}"
                )

        return list(fix_commits_dict.values())

    # Otherwise, use Selenium to extract from the URL
    try:
        # Set up Chrome options for headless browsing
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument(
            "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        )

        # Initialize the WebDriver
        driver = webdriver.Chrome(options=chrome_options)
        driver.implicitly_wait(10)  # Wait up to 10 seconds for elements to appear

        # Load the page
        driver.get(url)

        try:
            # Look for fix section or remediation information
            fix_sections = driver.find_elements(
                By.XPATH,
                "//*[contains(text(), 'Fix') or contains(text(), 'Patch') or contains(text(), 'Remediation')]",
            )

            section_texts = []
            for section in fix_sections:
                try:
                    parent = section.find_element(
                        By.XPATH,
                        "./ancestor::div[contains(@class, 'markdown-body') or contains(@class, 'section')]",
                    )
                    if parent:
                        section_texts.append(parent.text)
                except Exception:
                    pass  # Ignore if ancestor not found

            # Extract from text first
            for text in section_texts:
                text_commits = extract_fix_commits(text)
                for commit_info in text_commits:
                    sha = commit_info.get("sha")
                    if sha and (sha not in fix_commits_dict or commit_info.get("url")):
                        fix_commits_dict[sha] = commit_info

            # Look for links to GitHub PRs or commits
            links = driver.find_elements(By.TAG_NAME, "a")
            github_urls_to_process = set()
            for link in links:
                href = link.get_attribute("href")
                if href and "github.com" in href:
                    # Use extract_commit_from_url for consistency
                    commit_info = extract_commit_from_url(href)
                    if commit_info:
                        sha = commit_info.get("sha")
                        # Always prioritize URL from direct link
                        fix_commits_dict[sha] = commit_info
                    elif "/pull/" in href or "/issues/" in href:
                        # Collect GitHub URLs for later processing if needed
                        github_urls_to_process.add(href)

            # Process collected GitHub URLs if fix commits dict is still empty
            if not fix_commits_dict and github_urls_to_process:
                logger.info(
                    f"No direct commits found, processing {len(github_urls_to_process)} GitHub links from Huntr"
                )
                for github_url in github_urls_to_process:
                    try:
                        extracted_commits = []
                        if "/pull/" in github_url:
                            extracted_commits = extract_fix_commits_from_github_pr(
                                github_url
                            )
                        elif "/issues/" in github_url:
                            extracted_commits = extract_fix_commits_from_github_issue(
                                github_url
                            )

                        for commit_info in extracted_commits:
                            sha = commit_info.get("sha")
                            if sha and (
                                sha not in fix_commits_dict or commit_info.get("url")
                            ):
                                fix_commits_dict[sha] = commit_info
                    except Exception as e:
                        logger.warning(f"Error processing GitHub URL {github_url}: {e}")

        except Exception as e:
            logger.error(f"Error extracting fix details from Huntr.dev: {str(e)}")

        driver.quit()

    except Exception as e:
        logger.error(f"Error with Selenium while extracting from Huntr.dev: {str(e)}")

    return list(fix_commits_dict.values())


def setup_browser():
    """Set up a headless Chrome browser for web scraping.

    Returns:
        WebDriver: Configured Chrome WebDriver instance
    """
    # Set up Chrome options for headless browsing
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    )

    # Initialize the WebDriver
    driver = webdriver.Chrome(options=chrome_options)
    driver.implicitly_wait(10)  # Wait up to 10 seconds for elements to appear

    return driver


def extract_fix_commits_from_chromium(
    url: str, bug_description: Optional[str] = None
) -> List[Dict[str, Optional[str]]]:
    """
    Extract fix commits (SHA and URL) from OSS-Fuzz or Chromium bug reports.

    Args:
        url: OSS-Fuzz bug URL
        bug_description: Optional pre-extracted bug description text

    Returns:
        List[Dict[str, Optional[str]]]: List of extracted fix commit dictionaries
    """
    fix_commits_dict: Dict[str, Dict[str, Optional[str]]] = {}

    # Try to extract repo owner and name from bug description if it contains GitHub URLs
    repo_owner = None
    repo_name = None
    if bug_description:
        github_repo_match = re.search(
            r"https?://github\.com/([^/]+)/([^/]+)", bug_description
        )
        if github_repo_match:
            repo_owner, repo_name = github_repo_match.groups()
            # Remove any additional path components from repo_name
            repo_name = repo_name.split("/")[0]
            logger.debug(
                f"Extracted GitHub repo info from description: {repo_owner}/{repo_name}"
            )

    # If we already have the bug description, extract from it
    if bug_description:
        # First extract direct commit references from text
        text_commits = extract_fix_commits(bug_description, repo_owner, repo_name)
        for commit_info in text_commits:
            sha = commit_info.get("sha")
            if sha and (sha not in fix_commits_dict or commit_info.get("url")):
                fix_commits_dict[sha] = commit_info

        # Then look for GitHub issue/PR references in the description
        github_urls = re.findall(
            r"https://github\.com/[^/]+/[^/]+/(?:issues|pull)/\d+", bug_description
        )

        for github_url in github_urls:
            try:
                extracted_commits = []
                if "/pull/" in github_url:
                    extracted_commits = extract_fix_commits_from_github_pr(github_url)
                else:
                    extracted_commits = extract_fix_commits_from_github_issue(
                        github_url
                    )

                for commit_info in extracted_commits:
                    sha = commit_info.get("sha")
                    if sha and (sha not in fix_commits_dict or commit_info.get("url")):
                        fix_commits_dict[sha] = commit_info
            except Exception as e:
                logger.warning(
                    f"Error processing GitHub URL {github_url} from bug description: {e}"
                )

        return list(fix_commits_dict.values())

    # If no bug description is provided, try to extract it from the URL
    driver = None
    try:
        driver = setup_browser()
        driver.get(url)
        time.sleep(2)  # Wait for page to load

        try:
            # For Chromium bugs
            if "bugs.chromium.org" in url:
                # Check for commit links in the description and comments
                links = driver.find_elements(By.TAG_NAME, "a")
                github_urls_to_process = set()
                for link in links:
                    href = link.get_attribute("href")
                    if href:
                        # Use extract_commit_from_url for consistency (covers GitHub, GitLab, Bitbucket)
                        commit_info = extract_commit_from_url(
                            href, repo_owner, repo_name
                        )
                        if commit_info and isinstance(commit_info, dict):
                            sha = commit_info.get("sha")
                            if sha:  # Ensure sha is not None before using as dict key
                                # We need to handle the type conversion to satisfy mypy
                                temp_commit_dict1: Dict[str, Optional[str]] = {
                                    "sha": sha,
                                    "url": commit_info.get("url"),
                                }
                                fix_commits_dict[sha] = temp_commit_dict1
                        elif "github.com" in href and (
                            "/pull/" in href or "/issues/" in href
                        ):
                            github_urls_to_process.add(href)

                            # Also try to extract repo information if not already available
                            if not (repo_owner and repo_name):
                                github_repo_match = re.match(
                                    r"https?://github\.com/([^/]+)/([^/]+)", href
                                )
                                if github_repo_match:
                                    repo_owner, repo_name = github_repo_match.groups()
                                    # Remove any additional path components from repo_name
                                    repo_name = repo_name.split("/")[0]
                                    logger.debug(
                                        f"Extracted GitHub repo info from link: {repo_owner}/{repo_name}"
                                    )

                # Process collected GitHub URLs if fix commits dict is still empty
                if not fix_commits_dict and github_urls_to_process:
                    for github_url in github_urls_to_process:
                        try:
                            extracted_commits = []
                            if "/pull/" in github_url:
                                extracted_commits = extract_fix_commits_from_github_pr(
                                    github_url
                                )
                            else:
                                extracted_commits = (
                                    extract_fix_commits_from_github_issue(github_url)
                                )

                            for commit_info in extracted_commits:
                                sha = commit_info.get("sha")
                                if sha and (
                                    sha not in fix_commits_dict
                                    or commit_info.get("url")
                                ):
                                    fix_commits_dict[sha] = commit_info
                        except Exception as e:
                            logger.warning(
                                f"Error processing GitHub URL {github_url}: {e}"
                            )

            # For OSS-Fuzz bugs
            elif "bugs.chromium.org/p/oss-fuzz" in url:
                # Similar approach as Chromium bugs
                links = driver.find_elements(By.TAG_NAME, "a")
                github_urls_to_process = set()
                for link in links:
                    href = link.get_attribute("href")
                    if href:
                        # Use extract_commit_from_url for consistency
                        commit_info = extract_commit_from_url(
                            href, repo_owner, repo_name
                        )
                        if commit_info and isinstance(commit_info, dict):
                            sha = commit_info.get("sha")
                            if sha:  # Ensure sha is not None before using as dict key
                                # We need to handle the type conversion to satisfy mypy
                                temp_commit_dict2: Dict[str, Optional[str]] = {
                                    "sha": sha,
                                    "url": commit_info.get("url"),
                                }
                                fix_commits_dict[sha] = temp_commit_dict2
                        elif "github.com" in href and (
                            "/pull/" in href or "/issues/" in href
                        ):
                            github_urls_to_process.add(href)

                            # Also try to extract repo information if not already available
                            if not (repo_owner and repo_name):
                                github_repo_match = re.match(
                                    r"https?://github\.com/([^/]+)/([^/]+)", href
                                )
                                if github_repo_match:
                                    repo_owner, repo_name = github_repo_match.groups()
                                    # Remove any additional path components from repo_name
                                    repo_name = repo_name.split("/")[0]
                                    logger.debug(
                                        f"Extracted GitHub repo info from link: {repo_owner}/{repo_name}"
                                    )

                # Process GitHub URLs
                for github_url in github_urls_to_process:
                    try:
                        extracted_commits = []
                        if "/pull/" in github_url:
                            extracted_commits = extract_fix_commits_from_github_pr(
                                github_url
                            )
                        else:
                            extracted_commits = extract_fix_commits_from_github_issue(
                                github_url
                            )

                        for commit_info in extracted_commits:
                            sha = commit_info.get("sha")
                            if sha and (
                                sha not in fix_commits_dict or commit_info.get("url")
                            ):
                                fix_commits_dict[sha] = commit_info
                    except Exception as e:
                        logger.warning(f"Error processing GitHub URL {github_url}: {e}")

        except Exception as e:
            logger.error(f"Error extracting fix commits from Chromium UI: {e}")

        # Get the full page text for further processing
        try:
            page_text = driver.find_element(By.TAG_NAME, "body").text
            if page_text:
                # Extract commits from the page text
                text_commits = extract_fix_commits(page_text, repo_owner, repo_name)
                for commit_info in text_commits:
                    sha = commit_info.get("sha")
                    if sha and (sha not in fix_commits_dict or commit_info.get("url")):
                        fix_commits_dict[sha] = commit_info
        except Exception as e:
            logger.error(f"Error extracting text from Chromium page: {e}")

    except Exception as e:
        logger.error(f"Browser error extracting from Chromium: {e}")
    finally:
        try:
            if driver:
                driver.quit()
        except Exception:
            pass

    # Add default URLs for commits without URLs
    for commit in list(fix_commits_dict.values()):
        sha = commit.get("sha")
        # Only process if we have all required information
        if sha and not commit.get("url") and repo_owner and repo_name:
            # Explicit type assertion to address type checker
            repo_owner_str: str = repo_owner
            repo_name_str: str = repo_name
            commit["url"] = generate_default_github_url(
                repo_owner_str, repo_name_str, sha
            )

    return list(fix_commits_dict.values())


def extract_fix_commits_from_bugzilla(
    url: str, bug_description: Optional[str] = None
) -> List[Dict[str, Optional[str]]]:
    """
    Extract fix commits (SHA and URL) from Bugzilla bug reports (Red Hat, etc.).

    Args:
        url: Bugzilla bug URL
        bug_description: Optional pre-extracted bug description text

    Returns:
        List[Dict[str, Optional[str]]]: List of extracted fix commit dictionaries
    """
    fix_commits_dict: Dict[str, Dict[str, Optional[str]]] = {}

    # Try to extract repo owner and name from bug description if it contains GitHub URLs
    repo_owner = None
    repo_name = None
    if bug_description:
        github_repo_match = re.search(
            r"https?://github\.com/([^/]+)/([^/]+)", bug_description
        )
        if github_repo_match:
            repo_owner, repo_name = github_repo_match.groups()
            # Remove any additional path components from repo_name
            repo_name = repo_name.split("/")[0]
            logger.debug(
                f"Extracted GitHub repo info from description: {repo_owner}/{repo_name}"
            )

    # If we already have the bug description, extract from it
    if bug_description:
        # First extract direct commit references from text
        text_commits = extract_fix_commits(bug_description, repo_owner, repo_name)
        for commit_info in text_commits:
            sha = commit_info.get("sha")
            if sha and (sha not in fix_commits_dict or commit_info.get("url")):
                fix_commits_dict[sha] = commit_info

        # Then look for GitHub issue/PR references in the description
        github_urls = re.findall(
            r"https://github\.com/[^/]+/[^/]+/(?:issues|pull)/\d+", bug_description
        )

        for github_url in github_urls:
            try:
                extracted_commits = []
                if "/pull/" in github_url:
                    extracted_commits = extract_fix_commits_from_github_pr(github_url)
                else:
                    extracted_commits = extract_fix_commits_from_github_issue(
                        github_url
                    )

                for commit_info in extracted_commits:
                    sha = commit_info.get("sha")
                    if sha and (sha not in fix_commits_dict or commit_info.get("url")):
                        fix_commits_dict[sha] = commit_info
            except Exception as e:
                logger.warning(
                    f"Error processing GitHub URL {github_url} from bug description: {e}"
                )

        return list(fix_commits_dict.values())

    # If no bug description is provided, try to extract it from the URL
    driver = None
    try:
        driver = setup_browser()
        driver.get(url)
        time.sleep(2)  # Wait for page to load

        try:
            # For Red Hat Bugzilla
            if "bugzilla.redhat.com" in url:
                # Get all comments to check for GitHub issue links
                comments = driver.find_elements(
                    By.CSS_SELECTOR, "div.comment-text, pre.comment-text"
                )
                github_issue_urls_in_comments = set()

                for comment in comments:
                    comment_text = comment.text
                    if comment_text:
                        # Check for GitHub URLs in comments
                        issue_urls = re.findall(
                            r"https://github\.com/[^/]+/[^/]+/issues/\d+",
                            comment_text,
                        )
                        github_issue_urls_in_comments.update(issue_urls)

                        # Also try to extract repo information if not already available
                        if not (repo_owner and repo_name):
                            github_repo_match = re.search(
                                r"https?://github\.com/([^/]+)/([^/]+)", comment_text
                            )
                            if github_repo_match:
                                repo_owner, repo_name = github_repo_match.groups()
                                # Remove any additional path components from repo_name
                                repo_name = repo_name.split("/")[0]
                                logger.debug(
                                    f"Extracted GitHub repo info from comment: {repo_owner}/{repo_name}"
                                )

                # Process GitHub issue URLs found in comments
                for issue_url in github_issue_urls_in_comments:
                    try:
                        logger.info(
                            f"Found GitHub issue URL in Bugzilla comment: {issue_url}"
                        )
                        issue_commits = extract_fix_commits_from_github_issue(issue_url)
                        for commit_info in issue_commits:
                            sha = commit_info.get("sha")
                            if sha and (
                                sha not in fix_commits_dict or commit_info.get("url")
                            ):
                                fix_commits_dict[sha] = commit_info
                    except Exception as e:
                        logger.warning(
                            f"Error processing GitHub issue URL {issue_url}: {e}"
                        )

                # Look for links to commits and issues
                links = driver.find_elements(By.TAG_NAME, "a")
                github_issue_urls_in_links = set()
                for link in links:
                    href = link.get_attribute("href")
                    if href:
                        # Check for commit links (GitHub, GitLab, Bitbucket) using extract_commit_from_url
                        commit_info = extract_commit_from_url(
                            href, repo_owner, repo_name
                        )
                        if commit_info and isinstance(commit_info, dict):
                            sha = commit_info.get("sha")
                            if sha:  # Ensure sha is not None before using as dict key
                                # We need to handle the type conversion to satisfy mypy
                                temp_commit_dict: Dict[str, Optional[str]] = {
                                    "sha": sha,
                                    "url": commit_info.get("url"),
                                }
                                fix_commits_dict[sha] = temp_commit_dict
                        # Check for GitHub issue links specifically
                        elif "/issues/" in href and "github.com" in href:
                            if re.match(
                                r"https://github\.com/[^/]+/[^/]+/issues/\d+", href
                            ):
                                github_issue_urls_in_links.add(href)

                                # Also try to extract repo information if not already available
                                if not (repo_owner and repo_name):
                                    github_repo_match = re.match(
                                        r"https?://github\.com/([^/]+)/([^/]+)", href
                                    )
                                    if github_repo_match:
                                        repo_owner, repo_name = (
                                            github_repo_match.groups()
                                        )
                                        # Remove any additional path components from repo_name
                                        repo_name = repo_name.split("/")[0]
                                        logger.debug(
                                            f"Extracted GitHub repo info from link: {repo_owner}/{repo_name}"
                                        )

                # Process GitHub issue URLs found in links (if not processed already)
                for issue_url in github_issue_urls_in_links.difference(
                    github_issue_urls_in_comments
                ):
                    try:
                        logger.info(
                            f"Found GitHub issue URL in Bugzilla links: {issue_url}"
                        )
                        issue_commits = extract_fix_commits_from_github_issue(issue_url)
                        for commit_info in issue_commits:
                            sha = commit_info.get("sha")
                            if sha and (
                                sha not in fix_commits_dict or commit_info.get("url")
                            ):
                                fix_commits_dict[sha] = commit_info
                    except Exception as e:
                        logger.warning(
                            f"Error processing GitHub issue URL from links {issue_url}: {e}"
                        )

        except Exception as e:
            logger.error(f"Error extracting fix commits from Bugzilla UI: {e}")

        # Get the full page text for further processing
        try:
            page_text = driver.find_element(By.TAG_NAME, "body").text
            if page_text:
                # Extract commits from the page text
                text_commits = extract_fix_commits(page_text, repo_owner, repo_name)
                for commit_info in text_commits:
                    sha = commit_info.get("sha")
                    if sha and (sha not in fix_commits_dict or commit_info.get("url")):
                        fix_commits_dict[sha] = commit_info
        except Exception as e:
            logger.error(f"Error extracting text from Bugzilla page: {e}")

    except Exception as e:
        logger.error(f"Browser error extracting from Bugzilla: {e}")
    finally:
        try:
            if driver:
                driver.quit()
        except Exception:
            pass

    # Add default URLs for commits without URLs
    for commit in list(fix_commits_dict.values()):
        sha = commit.get("sha")
        # Only process if we have all required information
        if sha and not commit.get("url") and repo_owner and repo_name:
            # Explicit type assertion to address type checker
            repo_owner_str: str = repo_owner
            repo_name_str: str = repo_name
            commit["url"] = generate_default_github_url(
                repo_owner_str, repo_name_str, sha
            )

    return list(fix_commits_dict.values())


def extract_fix_commits_by_url(
    url: str, bug_description: Optional[str] = None
) -> List[Dict[str, Optional[str]]]:
    """
    Extract fix commits from a URL based on its source type.

    Args:
        url: Bug report URL
        bug_description: Optional pre-extracted bug description text

    Returns:
        List[Dict[str, Optional[str]]]: List of extracted fix commit dictionaries
    """
    source = is_supported_url(url)

    # Try to extract repo owner and name from URL for default GitHub URLs
    repo_owner = None
    repo_name = None

    # Check if it's a GitHub URL
    github_match = re.match(r"https?://github\.com/([^/]+)/([^/]+)", url)
    if github_match:
        repo_owner, repo_name = github_match.groups()
        # Remove any additional path components from repo_name
        repo_name = repo_name.split("/")[0]

    if not source:
        logger.debug(f"Unsupported URL for fix commit extraction: {url}")
        # Try basic extraction from description if available
        if bug_description:
            return extract_fix_commits(bug_description, repo_owner, repo_name)
        return []

    # Use specialized extractors based on source type
    if source == "GitHub Issue":
        commits = extract_fix_commits_from_github_issue(url)
    elif source == "GitHub Advisory":
        commits = extract_fix_commits_from_github_advisory(url)
    elif source == "Huntr":
        commits = extract_fix_commits_from_huntr(url, bug_description)
    elif source in ["Chromium", "OSS-Fuzz"]:
        commits = extract_fix_commits_from_chromium(url, bug_description)
    elif source == "Red Hat Bugzilla":
        commits = extract_fix_commits_from_bugzilla(url, bug_description)
    else:
        # For other sources, use basic extraction from description if available
        if bug_description:
            commits = extract_fix_commits(bug_description, repo_owner, repo_name)
        else:
            commits = []

    # Add default URLs for commits without URLs
    for commit in commits:
        if commit.get("sha") and not commit.get("url") and repo_owner and repo_name:
            commit["url"] = generate_default_github_url(
                repo_owner, repo_name, commit["sha"]
            )

    return commits


def extract_bug_description(url: str) -> str:
    """Extract bug description from a supported bug report URL using Selenium.

    Args:
        url: The URL of the bug report

    Returns:
        str: The extracted bug description or empty string if extraction failed
    """
    try:
        # Set up Chrome options for headless browsing
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument(
            "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        )

        # Initialize the WebDriver
        driver = webdriver.Chrome(options=chrome_options)
        driver.implicitly_wait(10)  # Wait up to 10 seconds for elements to appear

        # Load the page
        driver.get(url)

        # Extract content based on URL pattern
        bug_description = ""

        if url.startswith(("https://huntr.dev/bounties", "https://huntr.com/bounties")):
            # Huntr.dev bug reports
            try:
                # Get main content from markdown-body class
                markdown_elements = driver.find_elements(By.CLASS_NAME, "markdown-body")
                if markdown_elements:
                    bug_description = markdown_elements[0].text

                # Try to get additional information from write-up section
                write_up_div = driver.find_element(By.ID, "write-up")
                if write_up_div:
                    links = []
                    for a in write_up_div.find_elements(By.TAG_NAME, "a"):
                        href = a.get_attribute("href")
                        if href:
                            links.append(href)
                    if links:
                        bug_description += "\n\nRelevant Links:\n" + "\n".join(links)
            except Exception as e:
                logger.error(f"Error extracting from Huntr.dev: {e}")

        elif url.startswith(
            ("https://bugs.chromium.org/p/", "https://issues.oss-fuzz.com/issues/")
        ):
            # Chromium/OSS-Fuzz bug reports
            try:
                # Get main content from issue description
                elements = driver.find_elements(By.CLASS_NAME, "child")
                if elements:
                    bug_description = elements[0].text
            except Exception as e:
                logger.error(f"Error extracting from Chromium/OSS-Fuzz: {e}")

        elif url.startswith("https://github.com") and "/issues/" in url:
            # GitHub issues - using GitHub API instead of Selenium
            # Check if a specific comment is referenced in the URL
            comment_id_match = re.search(r"#issuecomment-(\d+)", url)
            comment_id = comment_id_match.group(1) if comment_id_match else None

            # Extract the basic issue info
            match = re.match(r"https://github\.com/([^/]+)/([^/]+)/issues/(\d+)", url)
            if match:
                owner, repo_name, issue_id = match.groups()
                github_token = os.getenv("GITHUB_TOKEN")

                if github_token:
                    # Try to use GitHub API
                    try:
                        g = Github(github_token)
                        repo = g.get_repo(f"{owner}/{repo_name}")
                        issue = repo.get_issue(int(issue_id))

                        # If a specific comment is referenced, extract only that comment
                        if comment_id:
                            try:
                                # Find the specific comment
                                found_comment = False
                                for comment in issue.get_comments():
                                    # The comment_id in the URL doesn't match the API's comment.id directly
                                    # Need to extract from the comment URL itself
                                    if f"issuecomment-{comment_id}" in comment.html_url:
                                        found_comment = True
                                        bug_description = (
                                            f"Issue: {owner}/{repo_name}#{issue_id}\n"
                                        )
                                        bug_description += f"Title: {issue.title}\n"
                                        bug_description += f"Referenced comment by {comment.user.login} on {comment.created_at}:\n\n"
                                        bug_description += comment.body

                                        # Extract attachments from the comment
                                        attachments = extract_github_attachments(
                                            comment.body
                                        )
                                        if attachments:
                                            bug_description += (
                                                "\n\nAttachments:\n"
                                                + "\n".join(set(attachments))
                                            )

                                        driver.quit()  # Close Selenium as we used the API
                                        return bug_description

                                if not found_comment:
                                    logger.warning(
                                        f"Comment ID {comment_id} not found in issue {owner}/{repo_name}#{issue_id}, fallback to regular extraction"
                                    )
                            except Exception as e:
                                logger.error(
                                    f"Error extracting specific comment {comment_id}: {e}"
                                )
                                # Fall back to regular issue extraction

                        # Regular issue extraction (if no specific comment or comment not found)
                        # Extract issue details
                        bug_description = f"Issue: {owner}/{repo_name}#{issue_id}\n"
                        bug_description += f"Title: {issue.title}\n"
                        bug_description += f"State: {issue.state}\n"
                        bug_description += f"Created by: {issue.user.login}\n"
                        bug_description += f"Created at: {issue.created_at}\n"

                        if issue.labels:
                            labels = [label.name for label in issue.labels]
                            bug_description += f"Labels: {', '.join(labels)}\n"

                        # Add issue body
                        bug_description += f"\nIssue Body:\n{issue.body}\n"

                        # Extract attachments from the body
                        attachments = extract_github_attachments(issue.body)

                        # Get comments
                        comments = []
                        try:
                            for comment in issue.get_comments():
                                comment_text = f"Comment by {comment.user.login} on {comment.created_at}:\n{comment.body}"
                                comments.append(comment_text)
                                attachments.extend(
                                    extract_github_attachments(comment.body)
                                )

                            if comments:
                                bug_description += (
                                    "\n\nComments:\n" + "\n\n---\n\n".join(comments)
                                )
                        except Exception as e:
                            logger.error(f"Error extracting comments via API: {e}")

                        # Add attachments if found
                        if attachments:
                            bug_description += "\n\nAttachments:\n" + "\n".join(
                                set(attachments)
                            )

                        # Extract commit references
                        commit_references = re.findall(
                            r"([0-9a-f]{40})", bug_description
                        )
                        if commit_references:
                            bug_description += "\n\nCommit References:\n" + "\n".join(
                                set(commit_references)
                            )

                        driver.quit()  # Close Selenium as we used the API
                        return bug_description

                    except (RateLimitExceededException, GithubException) as e:
                        logger.warning(
                            f"GitHub API error: {e}, falling back to Selenium"
                        )
                        # Fall back to Selenium extraction if API fails
                    except Exception as e:
                        logger.error(f"Unexpected error using GitHub API: {e}")
                        # Fall back to Selenium extraction if API fails
                else:
                    logger.warning(
                        "No GITHUB_TOKEN found, falling back to Selenium for GitHub issues"
                    )

            # Fallback to Selenium extraction
            try:
                # Extract owner, repo, and issue ID from URL
                match = re.match(
                    r"https://github\.com/([^/]+)/([^/]+)/issues/(\d+)", url
                )
                if match:
                    owner, repo_name, issue_id = match.groups()
                    issue_identifier = f"{owner}/{repo_name}#{issue_id}"
                else:
                    issue_identifier = "Unknown"

                # Check if a specific comment is referenced in the URL
                comment_id_match = re.search(r"#issuecomment-(\d+)", url)
                comment_id = comment_id_match.group(1) if comment_id_match else None

                # Get issue title for context regardless of which comment we're extracting
                title = "Unknown Title"
                try:
                    title_element = driver.find_element(
                        By.CSS_SELECTOR, "bdi.js-issue-title, h1.gh-header-title span"
                    )
                    title = title_element.text.strip()
                except Exception as e:
                    logger.error(f"Error extracting title: {e}")

                # If a specific comment is referenced, extract only that comment
                if comment_id:
                    try:
                        # Try to find the specific comment by its DOM ID
                        comment_container = driver.find_element(
                            By.CSS_SELECTOR, f"#issuecomment-{comment_id}"
                        )

                        # Get the comment author
                        try:
                            author_element = comment_container.find_element(
                                By.CSS_SELECTOR, ".author"
                            )
                            author = author_element.text.strip()
                        except Exception:
                            author = "Unknown"

                        # Get the comment body
                        try:
                            comment_body = comment_container.find_element(
                                By.CSS_SELECTOR, ".comment-body"
                            )
                            comment_text = comment_body.text.strip()

                            # Look for code blocks
                            code_blocks = comment_body.find_elements(
                                By.CSS_SELECTOR, "pre, code"
                            )
                            if code_blocks:
                                code_text = "\n\n".join(
                                    [block.text for block in code_blocks]
                                )
                                if code_text and len(code_text) > 0:
                                    comment_text += (
                                        f"\n\nCode/Stack Traces:\n```\n{code_text}\n```"
                                    )

                            # Build the description with just this comment
                            bug_description = f"Issue: {issue_identifier}\n"
                            bug_description += f"Title: {title}\n"
                            bug_description += f"Referenced comment by {author}:\n\n"
                            bug_description += comment_text

                            # Extract attachments from the comment
                            comment_html = comment_body.get_attribute("innerHTML")
                            if comment_html:
                                attachments = extract_github_attachments(comment_html)
                                if attachments:
                                    bug_description += "\n\nAttachments:\n" + "\n".join(
                                        set(attachments)
                                    )

                            return bug_description

                        except Exception as e:
                            logger.error(
                                f"Error extracting referenced comment {comment_id}: {e}"
                            )
                            # Fall back to regular issue extraction
                    except Exception as e:
                        logger.error(
                            f"Error finding referenced comment {comment_id}: {e}"
                        )
                        # Fall back to regular issue extraction

                # Continue with regular issue extraction if no specific comment or comment not found
                # Get issue metadata (author, date, etc.)
                try:
                    meta_element = driver.find_element(
                        By.CSS_SELECTOR, ".gh-header-meta"
                    )
                    meta_text = meta_element.text.strip()
                except Exception:
                    meta_text = ""

                # Get issue body - first try to get the rendered markdown content
                body = ""
                attachments = []
                try:
                    # Get the first comment which is the issue body
                    body_element = driver.find_element(
                        By.CSS_SELECTOR,
                        ".js-comment-container .comment-body, .timeline-comment-wrapper .comment-body",
                    )
                    if body_element:
                        # Look for code blocks specifically
                        code_blocks = body_element.find_elements(
                            By.CSS_SELECTOR, "pre, code"
                        )
                        if code_blocks:
                            code_text = "\n\n".join(
                                [block.text for block in code_blocks]
                            )
                            body = f"{body_element.text}\n\nCode Blocks:\n```\n{code_text}\n```"
                        else:
                            body = body_element.text.strip()

                        # Extract attachments from the issue body
                        body_html = body_element.get_attribute("innerHTML")
                        if body_html:
                            attachments.extend(extract_github_attachments(body_html))
                except Exception as e:
                    logger.error(f"Error extracting body: {e}")

                # Build the initial bug description
                bug_description = f"Issue: {issue_identifier}\nTitle: {title}\n"
                if meta_text:
                    bug_description += f"Metadata: {meta_text}\n"
                bug_description += f"\nIssue Body:\n{body}"

                # Get all comments (not just the first 5)
                try:
                    # Look for timeline items which include comments
                    comment_containers = driver.find_elements(
                        By.CSS_SELECTOR, ".js-timeline-item"
                    )

                    # If we can't find timeline items, try direct comment containers
                    if not comment_containers:
                        comment_containers = driver.find_elements(
                            By.CSS_SELECTOR, ".js-comment-container"
                        )

                    if (
                        comment_containers and len(comment_containers) > 1
                    ):  # Skip the first one as it's usually the issue body
                        comment_texts = []

                        for i, container in enumerate(comment_containers[1:]):
                            try:
                                # Try to get comment author
                                try:
                                    author_element = container.find_element(
                                        By.CSS_SELECTOR, ".author"
                                    )
                                    author = author_element.text.strip()
                                except Exception:
                                    author = "Unknown"

                                # Try to get comment body
                                try:
                                    comment_body = container.find_element(
                                        By.CSS_SELECTOR, ".comment-body"
                                    )
                                    comment_text = comment_body.text.strip()

                                    # Look for code blocks
                                    code_blocks = comment_body.find_elements(
                                        By.CSS_SELECTOR, "pre, code"
                                    )
                                    if code_blocks:
                                        code_text = "\n\n".join(
                                            [block.text for block in code_blocks]
                                        )
                                        if code_text and len(code_text) > 0:
                                            comment_text += f"\n\nCode/Stack Traces:\n```\n{code_text}\n```"

                                    # Add the comment with author
                                    comment_texts.append(
                                        f"Comment by {author}:\n{comment_text}"
                                    )

                                    # Extract attachments from the comment
                                    comment_html = comment_body.get_attribute(
                                        "innerHTML"
                                    )
                                    if comment_html:
                                        attachments.extend(
                                            extract_github_attachments(comment_html)
                                        )
                                except Exception as e:
                                    logger.error(
                                        f"Error extracting comment {i + 1}: {e}"
                                    )
                            except Exception:
                                continue

                        if comment_texts:
                            bug_description += "\n\nComments:\n" + "\n\n---\n\n".join(
                                comment_texts
                            )
                except Exception as e:
                    logger.error(f"Error extracting comments: {e}")

                # Add any attachments found
                if attachments:
                    bug_description += "\n\nAttachments:\n" + "\n".join(
                        set(attachments)
                    )

                # Look for specific commit references in the text
                commit_references = re.findall(r"([0-9a-f]{40})", bug_description)
                if commit_references:
                    bug_description += "\n\nCommit References:\n" + "\n".join(
                        set(commit_references)
                    )

            except Exception as e:
                logger.error(f"Error extracting from GitHub issue: {e}")
        elif url.startswith("https://bugs.php.net/bug.php"):
            # PHP bug reports
            try:
                # Extract metadata from bug header
                bug_id = "Unknown"
                summary = "Unknown"
                php_version = "Unknown"
                status = "Unknown"
                cve_id = None
                assigned_to = "Unknown"

                # Extract bug ID and summary
                try:
                    bug_id_element = driver.find_element(
                        By.CSS_SELECTOR, "#bugheader #number"
                    )
                    if bug_id_element:
                        bug_id_match = re.search(r"#(\d+)", bug_id_element.text)
                        if bug_id_match:
                            bug_id = bug_id_match.group(1)

                    summary_element = driver.find_element(
                        By.CSS_SELECTOR, "#bugheader #summary"
                    )
                    if summary_element:
                        summary = summary_element.text.strip()
                except Exception as e:
                    logger.error(f"Error extracting PHP bug ID/summary: {e}")

                # Extract other metadata
                try:
                    # PHP Version
                    php_version_element = driver.find_element(
                        By.XPATH, "//th[text()='PHP Version:']/following-sibling::td"
                    )
                    if php_version_element:
                        php_version = php_version_element.text.strip()

                    # Status
                    status_element = driver.find_element(
                        By.XPATH, "//th[text()='Status:']/following-sibling::td"
                    )
                    if status_element:
                        status = status_element.text.strip()

                    # CVE-ID
                    cve_element = driver.find_element(
                        By.XPATH, "//th[text()='CVE-ID:']/following-sibling::td"
                    )
                    if cve_element:
                        cve_text = cve_element.text.strip()
                        if cve_text and cve_text != "None":
                            cve_id = cve_text

                    # Assigned to
                    assigned_element = driver.find_element(
                        By.XPATH, "//th[text()='Assigned:']/following-sibling::td"
                    )
                    if assigned_element:
                        assigned_to = assigned_element.text.strip()
                except Exception as e:
                    logger.error(f"Error extracting PHP bug metadata: {e}")

                # Build the initial bug description with metadata
                bug_description = f"PHP Bug ID: {bug_id}\nSummary: {summary}\nStatus: {status}\nPHP Version: {php_version}\nAssigned: {assigned_to}"
                if cve_id:
                    bug_description += f"\nCVE-ID: {cve_id}"

                # Extract comments
                comments: List[PHPComment] = []
                try:
                    comment_elements = driver.find_elements(
                        By.CSS_SELECTOR, "div.comment"
                    )
                    for i, comment_element in enumerate(comment_elements):
                        try:
                            # Extract author and timestamp
                            author_element = comment_element.find_element(
                                By.CSS_SELECTOR, "strong"
                            )
                            author_info = (
                                author_element.text.strip()
                                if author_element
                                else "Unknown"
                            )

                            # Extract comment text
                            comment_text_element = comment_element.find_element(
                                By.CSS_SELECTOR, "pre.note"
                            )
                            comment_text = (
                                comment_text_element.text.strip()
                                if comment_text_element
                                else ""
                            )

                            # Extract links from comment
                            links = []
                            link_elements = (
                                comment_text_element.find_elements(By.TAG_NAME, "a")
                                if comment_text_element
                                else []
                            )
                            for link in link_elements:
                                href = link.get_attribute("href")
                                if href:
                                    links.append(href)

                            # Add comment to list
                            comments.append(
                                PHPComment(author_info, comment_text, links)
                            )
                        except Exception as e:
                            logger.error(f"Error extracting PHP comment {i + 1}: {e}")
                            continue
                except Exception as e:
                    logger.error(f"Error finding PHP bug comments: {e}")

                # Add first comment as main description if available
                if comments and comments[0].text:
                    bug_description += f"\n\nDescription:\n{comments[0].text}"

                # Add remaining comments
                if len(comments) > 1:
                    bug_description += "\n\nComments:"
                    for i, comment in enumerate(comments[1:], 1):
                        if "Automatic comment on behalf of" in comment.text:
                            continue
                        bug_description += (
                            f"\n\n[Comment {i}] {comment.author_info}\n{comment.text}"
                        )
                        if comment.links:
                            bug_description += f"\nLinks: {', '.join(comment.links)}"

                # Look for specific commit references in the text
                commit_references = re.findall(r"([0-9a-f]{40})", bug_description)
                if commit_references:
                    bug_description += "\n\nCommit References:\n" + "\n".join(
                        set(commit_references)
                    )
            except Exception as e:
                logger.error(f"Error extracting from PHP bugs: {e}")

        elif url.startswith("https://bugzilla.redhat.com/show_bug.cgi"):
            # Red Hat Bugzilla bug reports
            try:
                # Extract bug ID from URL for context
                bug_id_match = re.search(r"id=(\d+)", url)
                bug_id = bug_id_match.group(1) if bug_id_match else "Unknown"

                # Get the bug summary (title)
                title = "Unknown Title"
                try:
                    title_element = driver.find_element(
                        By.ID, "short_desc_nonedit_display"
                    )
                    title = title_element.text.strip()
                except Exception as e:
                    logger.error(f"Error extracting Bugzilla title: {e}")

                # Get the bug description from the first comment
                description = ""
                try:
                    # The first comment contains the bug description
                    first_comment = driver.find_element(
                        By.CSS_SELECTOR, ".bz_first_comment"
                    )
                    description = first_comment.text.strip()
                except Exception as e:
                    logger.error(f"Error extracting Bugzilla description: {e}")

                # Build the bug description
                bug_description = f"Bugzilla ID: {bug_id}\nTitle: {title}\n"

                # Add the full description
                if description:
                    bug_description += f"\n{description}\n"

                # Get comments (excluding the first one which is the description)
                try:
                    bugzilla_comments = driver.find_elements(
                        By.CSS_SELECTOR, ".bz_comment:not(.bz_first_comment)"
                    )
                    if bugzilla_comments:
                        comment_texts = []
                        for i, comment_element in enumerate(
                            bugzilla_comments[:5]
                        ):  # Limit to first 5 additional comments
                            try:
                                # Try to get comment author and text
                                comment_head_element = comment_element.find_element(
                                    By.CSS_SELECTOR, ".bz_comment_head"
                                )
                                comment_text_element = comment_element.find_element(
                                    By.CSS_SELECTOR, ".bz_comment_text"
                                )

                                if comment_head_element and comment_text_element:
                                    comment_texts.append(
                                        f"{comment_head_element.text.strip()}\n{comment_text_element.text.strip()}"
                                    )
                            except Exception as e:
                                logger.error(
                                    f"Error extracting Bugzilla comment {i + 1}: {e}"
                                )

                        if comment_texts:
                            bug_description += "\n\nComments:\n" + "\n\n---\n\n".join(
                                comment_texts
                            )
                except Exception as e:
                    logger.error(f"Error extracting Bugzilla comments: {e}")

                # Extract attachments
                try:
                    attachments = []
                    try:
                        attachment_table = driver.find_element(
                            By.ID, "attachment_table"
                        )
                        attachment_rows = attachment_table.find_elements(
                            By.TAG_NAME, "tr"
                        )
                        for row in attachment_rows[1:]:  # Skip header row
                            try:
                                cells = row.find_elements(By.TAG_NAME, "td")
                                if len(cells) >= 2:  # Need at least 2 cells
                                    # Find the link inside the first cell
                                    link_elements = cells[0].find_elements(
                                        By.TAG_NAME, "a"
                                    )
                                    if link_elements:
                                        link = link_elements[0]
                                        attachment_id = link.get_attribute("href")
                                        attachment_url = ""
                                        if attachment_id:
                                            # Extract just the ID from the href
                                            id_match = re.search(
                                                r"id=(\d+)", attachment_id
                                            )
                                            if id_match:
                                                attachment_id = id_match.group(1)
                                                # Construct full URL to the attachment
                                                base_url = "https://bugzilla.redhat.com"
                                                attachment_url = f"{base_url}/attachment.cgi?id={attachment_id}"

                                        # Get description (visible text of the link)
                                        attachment_desc = link.text.strip()

                                        # Get additional info from second cell if available
                                        attachment_info = f"Attachment {attachment_id}: {attachment_desc}"
                                        if attachment_url:
                                            attachment_info += (
                                                f" [Link: {attachment_url}]"
                                            )

                                        attachments.append(attachment_info)
                            except Exception as e:
                                logger.error(f"Error extracting attachment row: {e}")
                                continue
                    except NoSuchElementException:
                        # It's okay if there's no attachment table
                        pass

                    if attachments:
                        bug_description += "\n\nAttachments:\n" + "\n".join(attachments)
                except Exception as e:
                    logger.error(f"Error extracting Bugzilla attachments: {e}")

            except Exception as e:
                logger.error(f"Error extracting from Red Hat Bugzilla: {e}")

        elif url.startswith("http://www.openwall.com/lists/"):
            # Openwall mailing list reports
            # TODO: We need to handle the case where the page includes multiple CVE instances with zipped PoC files
            # ref: https://www.openwall.com/lists/oss-security/2017/06/30/1 (for CVE-2017-1000126/1000127/1000128)
            try:
                # Extract message details from URL
                message_match = re.search(r"/lists/([\w\-]+)/(\d+)/(\d+)/(\d+)", url)
                list_name, year, month, msg_num = (
                    message_match.groups()
                    if message_match
                    else ("Unknown", "Unknown", "Unknown", "Unknown")
                )

                logger.info(
                    f"Processing Openwall message: {list_name}/{year}/{month}/{msg_num}"
                )

                # Try different selectors for the content
                content = ""
                raw_html = ""
                links = []

                # Strategy 1: Look for pre tag with white-space: pre-wrap style
                try:
                    content_element = driver.find_element(
                        By.CSS_SELECTOR, "pre[style*='white-space: pre-wrap']"
                    )
                    if content_element:
                        logger.info(
                            "Found content element with pre[style*='white-space: pre-wrap'] selector"
                        )
                        raw_html = content_element.get_attribute("innerHTML") or ""
                except NoSuchElementException:
                    logger.warning("No pre tag with white-space: pre-wrap style found")

                # Strategy 2: Look for any pre tag
                if not raw_html:
                    try:
                        content_element = driver.find_element(By.CSS_SELECTOR, "pre")
                        if content_element:
                            logger.info("Found content element with pre selector")
                            raw_html = content_element.get_attribute("innerHTML") or ""
                    except NoSuchElementException:
                        logger.warning("No pre tag found")

                # If we have HTML content, process it
                if raw_html:
                    logger.info(f"Raw HTML length: {len(raw_html)}")
                    logger.info(f"Raw HTML excerpt: {raw_html[:200]}...")

                    # Extract links using regex
                    link_matches = re.findall(
                        r'<a\s+href="([^"]+)"[^>]*>([^<]+)</a>', raw_html
                    )
                    for href, text in link_matches:
                        links.append(f"[{text.strip()}] {href}")

                    # Extract text content from HTML
                    try:
                        soup = BeautifulSoup(raw_html, "html.parser")
                        content = soup.get_text()
                        logger.info(
                            f"Extracted text content from HTML (length: {len(content)})"
                        )
                    except Exception as e:
                        logger.error(f"Error parsing HTML content: {e}")

                # If we still don't have content, try getting the body text
                if not content:
                    try:
                        body_element = driver.find_element(By.CSS_SELECTOR, "body")
                        content = body_element.text
                        logger.info("Extracted content from body element")
                    except Exception as e:
                        logger.error(f"Error extracting body: {e}")

                # Extract subject from the page title
                subject = ""
                try:
                    title_element = driver.find_element(By.CSS_SELECTOR, "title")
                    if title_element:
                        title_text = title_element.text
                        logger.info(f"Page title: {title_text}")
                        # Titles are usually in format "Subject - List Name"
                        if " - " in title_text:
                            subject = title_text.split(" - ")[0].strip()
                except Exception as e:
                    logger.error(f"Error extracting title: {e}")

                # Extract message metadata from content
                metadata = {}
                if content:
                    # Look for message headers at the beginning of the content
                    message_id_match = re.search(r"Message-ID:\s*(.+)", content)
                    if message_id_match:
                        metadata["Message-ID"] = message_id_match.group(1).strip()

                    date_match = re.search(r"Date:\s*(.+)", content)
                    if date_match:
                        metadata["Date"] = date_match.group(1).strip()

                    from_match = re.search(r"From:\s*(.+)", content)
                    if from_match:
                        metadata["From"] = from_match.group(1).strip()

                    subject_match = re.search(r"Subject:\s*(.+)", content)
                    if subject_match and not subject:
                        subject = subject_match.group(1).strip()

                # Build the bug description
                bug_description = "Openwall Report\n"
                bug_description += f"List: {list_name}\n"

                # Add metadata fields if found
                for key, value in metadata.items():
                    bug_description += f"{key}: {value}\n"

                if subject:
                    bug_description += f"Subject: {subject}\n"

                bug_description += f"Date: {year}/{month}\n"
                bug_description += f"Message: #{msg_num}\n\n"

                if content:
                    bug_description += content

                # Add extracted links if we found any
                if links:
                    bug_description += "\n\nLinks:\n"
                    bug_description += "\n".join(links)

            except Exception as e:
                logger.error(f"Error extracting from Openwall: {e}")
                traceback.print_exc()

        elif "advisory" in url.lower() and "github.com" in url:
            # GitHub Security Advisories
            try:
                # Get advisory content
                summary_element = driver.find_element(By.CSS_SELECTOR, ".markdown-body")
                if summary_element:
                    bug_description = summary_element.text
            except Exception as e:
                logger.error(f"Error extracting from GitHub Advisory: {e}")

        elif url.startswith("https://github.com") and "/security/advisories/" in url:
            # GitHub Security Advisories - using GitHub API
            advisory_id_match = re.search(
                r"/(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", url
            )

            if advisory_id_match:
                ghsa_id = advisory_id_match.group(1)
                github_token = os.getenv("GITHUB_TOKEN")

                if github_token:
                    # Try to use GitHub API
                    try:
                        g = Github(github_token)
                        advisory = g.get_global_advisory(ghsa_id)

                        # Build comprehensive advisory description
                        bug_description = f"Advisory ID: {ghsa_id}\n"

                        if advisory.severity:
                            bug_description += f"Severity: {advisory.severity}\n"

                        if advisory.summary:
                            bug_description += f"Title: {advisory.summary}\n"

                        if advisory.published_at:
                            bug_description += f"Published: {advisory.published_at}\n"

                        if advisory.updated_at:
                            bug_description += f"Updated: {advisory.updated_at}\n"

                        # Add vulnerabilities and affected packages
                        if (
                            hasattr(advisory, "vulnerabilities")
                            and advisory.vulnerabilities
                        ):
                            try:
                                affected_packages = []
                                for vuln in advisory.vulnerabilities:
                                    if hasattr(vuln, "package") and vuln.package:
                                        package_info = f"Package: {vuln.package.name}"
                                        if (
                                            hasattr(vuln, "vulnerable_version_range")
                                            and vuln.vulnerable_version_range
                                        ):
                                            package_info += f" (Vulnerable: {vuln.vulnerable_version_range})"
                                        affected_packages.append(package_info)

                                if affected_packages:
                                    bug_description += (
                                        "\n\nAffected Packages:\n"
                                        + "\n".join(affected_packages)
                                    )
                            except Exception as e:
                                logger.error(
                                    f"Error extracting vulnerability details: {e}"
                                )

                        # Add full description
                        if advisory.description:
                            bug_description += (
                                f"\n\nDescription:\n{advisory.description}\n"
                            )

                        # Add references if available
                        if hasattr(advisory, "references") and advisory.references:
                            bug_description += "\n\nReferences:\n" + "\n".join(
                                advisory.references
                            )

                        # Add CVE identifiers
                        if hasattr(advisory, "identifiers") and advisory.identifiers:
                            identifiers = []
                            for identifier in advisory.identifiers:
                                try:
                                    if hasattr(identifier, "type") and hasattr(
                                        identifier, "value"
                                    ):
                                        identifiers.append(
                                            f"{identifier.type}: {identifier.value}"
                                        )
                                except AttributeError:
                                    # Handle dictionary-like structure if needed
                                    if (
                                        isinstance(identifier, dict)
                                        and "type" in identifier
                                        and "value" in identifier
                                    ):
                                        identifiers.append(
                                            f"{identifier['type']}: {identifier['value']}"
                                        )

                            if identifiers:
                                bug_description += "\n\nIdentifiers:\n" + "\n".join(
                                    identifiers
                                )

                        # Extract any credit information
                        if hasattr(advisory, "credits") and advisory.credits:
                            credits = []
                            for credit in advisory.credits:
                                if hasattr(credit, "user") and hasattr(
                                    credit.user, "login"
                                ):
                                    credits.append(f"{credit.user.login}")
                                elif (
                                    hasattr(credit, "user")
                                    and isinstance(credit.user, dict)
                                    and "login" in credit.user
                                ):
                                    credits.append(f"{credit.user['login']}")

                            if credits:
                                bug_description += "\n\nCredits:\n" + "\n".join(credits)

                        driver.quit()  # Close Selenium as we used the API
                        return bug_description

                    except (RateLimitExceededException, GithubException) as e:
                        logger.warning(
                            f"GitHub API error for advisory: {e}, falling back to Selenium"
                        )
                    except Exception as e:
                        logger.error(
                            f"Unexpected error using GitHub API for advisory: {e}"
                        )
                else:
                    logger.warning(
                        "No GITHUB_TOKEN found, falling back to Selenium for GitHub advisory"
                    )

            # Fallback to Selenium for GitHub Security Advisories
            try:
                # Get advisory ID for context
                advisory_id = (
                    advisory_id_match.group(1) if advisory_id_match else "Unknown"
                )

                # Get advisory title
                title = "Unknown Title"
                try:
                    title_element = driver.find_element(
                        By.CSS_SELECTOR, ".Box-title, h1.gh-header-title"
                    )
                    title = title_element.text.strip()
                except Exception:
                    pass

                # Get advisory description
                description = ""
                try:
                    description_element = driver.find_element(
                        By.CSS_SELECTOR, ".markdown-body"
                    )
                    description = description_element.text.strip()
                except Exception:
                    pass

                # Get severity if available
                severity = "Unknown"
                try:
                    severity_element = driver.find_element(
                        By.CSS_SELECTOR, ".Label--security, .security-label"
                    )
                    severity = severity_element.text.strip()
                except Exception:
                    pass

                # Build the description
                bug_description = f"Advisory ID: {advisory_id}\n"

                if severity and severity != "Unknown":
                    bug_description += f"Severity: {severity}\n"

                if title and title != "Unknown Title":
                    bug_description += f"Title: {title}\n"

                if description:
                    bug_description += f"\nDescription:\n{description}\n"

                # Try to extract affected packages
                try:
                    # First try to find a section with affected packages heading
                    affected_section = None
                    sections = driver.find_elements(By.CSS_SELECTOR, ".Box-row")
                    for section in sections:
                        section_text = section.text.lower()
                        if "affected packages" in section_text:
                            affected_section = section
                            break

                    if affected_section:
                        affected_text = affected_section.text.strip()
                        if affected_text:
                            bug_description += f"\nAffected Packages:\n{affected_text}"
                except Exception:
                    pass

                # Extract references/links
                references = []
                try:
                    link_elements = driver.find_elements(
                        By.CSS_SELECTOR, ".markdown-body a"
                    )
                    for link in link_elements:
                        href = link.get_attribute("href")
                        if href and href not in references:
                            references.append(href)

                    if references:
                        bug_description += "\n\nReferences:\n" + "\n".join(references)
                except Exception:
                    pass

            except Exception as e:
                logger.error(f"Error extracting from GitHub Advisory: {e}")

        driver.quit()
        return bug_description

    except Exception as e:
        logger.error(f"Failed to extract bug description from {url}: {str(e)}")
        traceback.print_exc()
        return ""


def is_supported_url(url: str) -> Optional[str]:
    """Check if a URL is from a supported bug report site.

    Args:
        url: The URL to check

    Returns:
        Optional[str]: The name of the source if the URL is supported, None otherwise
    """
    supported_patterns = {
        "Huntr": r"https?://huntr\.(dev|com)/bounties",
        "Chromium": r"https?://bugs\.chromium\.org/p/",
        "OSS-Fuzz": r"https?://issues\.oss-fuzz\.com/issues/",
        "GitHub Issue": r"https?://github\.com/.+/issues/\d+(#issuecomment-\d+)?",  # GitHub issues, optionally with comment reference
        "GitHub Advisory": r"https?://github\.com/.+/security/advisories/(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})",
        "PHP Bugs": r"https?://bugs\.php\.net/bug\.php",
        "Red Hat Bugzilla": r"https?://bugzilla\.redhat\.com/show_bug\.cgi\?id=\d+",  # Red Hat Bugzilla pattern
        # "Openwall": r"https?://www\.openwall\.com/lists/[\w\-]+/\d+/\d+/\d+",  # Openwall mailing list pattern
    }

    for source, pattern in supported_patterns.items():
        if re.match(pattern, url):
            return source

    return None


def is_cve_id(bug_id: str) -> bool:
    """Check if the bug ID follows the CVE format (CVE-YYYY-NNNNN)."""
    return bool(re.match(r"^CVE-\d{4}-\d+$", bug_id))


def is_osv_id(bug_id: str) -> bool:
    """Check if the bug ID follows the OSV format."""
    # OSV IDs typically follow the format GHSA-XXXX-XXXX-XXXX or PYSEC-XXXX
    # Adjust this if there are other OSV ID formats in your dataset
    return bool(re.match(r"^(GHSA|PYSEC|RUSTSEC|GO|OSV)-[\w\-]+$", bug_id))


def is_valid_vuln_type(bug_id: str, vuln_type: str) -> bool:
    """Check if the bug ID matches the requested vulnerability type."""
    if vuln_type == "ALL":
        return True
    elif vuln_type == "CVE":
        return is_cve_id(bug_id)
    elif vuln_type == "OSV":
        return is_osv_id(bug_id)
    return False


def extract_commit_from_url(
    url: str, repo_owner: Optional[str] = None, repo_name: Optional[str] = None
) -> Optional[Dict[str, Optional[str]]]:
    """
    Extract commit hash and URL from a URL if it's a direct link to a commit.

    Args:
        url: A URL that might contain a commit reference
        repo_owner: Optional GitHub repository owner for default URL generation
        repo_name: Optional GitHub repository name for default URL generation

    Returns:
        Optional[Dict[str, Optional[str]]]: Dictionary {"sha": sha, "url": url} if found, None otherwise
    """
    # Combined pattern for GitHub, GitLab, Bitbucket - captures URL and SHA
    # Improved pattern to ensure SHA has at least one alphabetic hex char (a-f) or is exactly 40 chars
    commit_pattern = r"(https?://(?:github\.com|gitlab\.(?:com|org)|bitbucket\.org)/[^/]+/[^/]+/(?:commit|commits|-/commit)/([0-9a-f]*[a-f][0-9a-f]*|[0-9a-f]{40}))"
    match = re.search(commit_pattern, url)
    if match:
        full_url, sha = match.groups()
        # Validate that SHA looks legitimate (right length and format)
        if (
            re.match(r"^[0-9a-f]{7,40}$", sha)
            and ((len(sha) >= 7 and len(sha) <= 12) or len(sha) == 40)
            and re.search(r"[a-f]", sha)
        ):  # Ensure at least one a-f character
            # Normalize URL to use "commit" instead of "commits"
            normalized_url = re.sub(
                r"(github\.com|gitlab\.(?:com|org)|bitbucket\.org)/([^/]+)/([^/]+)/commits/",
                r"\1/\2/\3/commit/",
                full_url,
            )
            return {"sha": sha, "url": normalized_url}
        logger.debug(
            f"Skipping potential commit {sha} as it doesn't match expected format"
        )

    # Check for just a commit hash in the URL
    sha_pattern = r"\b([0-9a-f]*[a-f][0-9a-f]*|[0-9a-f]{40})\b"
    for sha in re.findall(sha_pattern, url):
        # Only consider it a commit if it's at least 7 chars and matches standard format
        if (
            re.match(r"^[0-9a-f]+$", sha)
            and len(sha) >= 7
            and (len(sha) <= 12 or len(sha) == 40)
            and re.search(r"[a-f]", sha)  # Ensure at least one a-f character
        ):
            # Try to generate a default URL if repository info is available
            default_url = None
            if repo_owner and repo_name:
                # Ensure types are correct for function call
                sha_str: str = sha  # Explicit cast to satisfy type checker
                repo_owner_str: str = repo_owner
                repo_name_str: str = repo_name
                default_url = generate_default_github_url(
                    repo_owner_str, repo_name_str, sha_str
                )

            if default_url:
                logger.debug(
                    f"Generated default GitHub URL for commit {sha}: {default_url}"
                )
                return {"sha": sha, "url": default_url}
            else:
                # If we can't generate a URL but found a commit hash, report it
                logger.debug(
                    f"Found commit hash {sha} in URL, but couldn't generate a default URL"
                )
                return {"sha": sha, "url": None}

    # Fallback patterns can be added here if the combined one misses cases,
    # but the combined one should cover most standard commit URLs.
    # For example:
    # github_commit_pattern = r"(https?://github\.com/[^/]+/[^/]+/commit(?:s)?/([0-9a-f]{7,40}))"
    # gitlab_commit_pattern = r"(https?://gitlab\.(?:com|org)/[^/]+/[^/]+/(?:-/)?commit(?:s)?/([0-9a-f]{7,40}))"
    # bitbucket_commit_pattern = r"(https?://bitbucket\.org/[^/]+/[^/]+/commits?/([0-9a-f]{7,40}))"
    # ... check each pattern if the combined one fails ...

    return None


def extract_descriptions_for_entry(
    entry: Dict[str, Any], descriptions_dir: Path, source_counts: Dict[str, int]
) -> Dict[str, Any]:
    """Extract bug descriptions from reference URLs for a single entry.

    Args:
        entry: Dictionary containing vulnerability information
        descriptions_dir: Directory to store extracted descriptions
        source_counts: Dictionary to track the count of sources

    Returns:
        Dict: Updated entry with bug descriptions and extracted fix commits
    """
    # Create bug ID specific directory
    bug_id = entry["id"]
    bug_dir = descriptions_dir / bug_id
    bug_dir.mkdir(parents=True, exist_ok=True)

    # Keep track of supported URLs with their sources
    supported_urls_with_sources = []
    for url in entry.get("references", []):
        source = is_supported_url(url)
        if source:
            supported_urls_with_sources.append((url, source))

    # Use a dictionary keyed by SHA to store extracted commits, prioritizing entries with URLs
    extracted_fix_commits_dict: Dict[str, Dict[str, Optional[str]]] = {}

    # Check if the entry already has a fixed commit (just the SHA string initially)
    original_fixed_commit_sha = entry.get("fixed", "").strip()

    # Extract repository owner and name for GitHub repositories
    repo_owner = None
    repo_name = None
    repo_url = entry.get("repo_url", "")
    if repo_url:
        github_match = re.match(r"https?://github\.com/([^/]+)/([^/]+)", repo_url)
        if github_match:
            repo_owner, repo_name = github_match.groups()
            # Remove any additional path components from repo_name
            repo_name = repo_name.split("/")[0]

    # First, check all reference URLs for direct commit links
    commit_urls = []
    for url in entry.get("references", []):
        commit_info = extract_commit_from_url(url)
        if commit_info:
            sha = commit_info.get("sha")
            if sha:
                # Always update with the URL from direct link
                extracted_fix_commits_dict[sha] = commit_info
            commit_urls.append(url)
            logger.info(f"Found commit {sha} in reference URL: {url}")

    # For OSV entries, try to convert the "fixed" field to an entry with URL
    if original_fixed_commit_sha and is_osv_id(bug_id):
        # Convert string SHA to a dictionary with SHA and URL (if available)
        sha = original_fixed_commit_sha
        # If we don't already have this SHA with a URL, add it
        if sha not in extracted_fix_commits_dict:
            # Try to create a URL if we have repo info
            url = None
            if repo_owner and repo_name:
                url = generate_default_github_url(repo_owner, repo_name, sha)

            extracted_fix_commits_dict[sha] = {"sha": sha, "url": url}
            logger.info(f"Added OSV fixed commit: {sha}")

    # Extract from descriptions in sources by URL
    descriptions = []
    if supported_urls_with_sources:
        # Create a dictionary to track source counts for this specific bug
        bug_source_counts: Dict[str, int] = {}

        for url, source in supported_urls_with_sources:
            source_counts[source] = source_counts.get(source, 0) + 1

            # Track source count for this specific bug to handle multiple URLs from same source
            bug_source_counts[source] = bug_source_counts.get(source, 0) + 1
            source_instance = bug_source_counts[source]

            logger.info(f"Processing {source} URL for descriptions: {url}")

            # Create a unique filename with source instance number if multiple reports from same source
            filename_base = f"{source.lower().replace(' ', '_')}"
            if source_instance > 1:
                filename_base += f"_{source_instance}"
            description_file = bug_dir / f"{filename_base}.txt"

            description = None

            if description_file.exists():
                try:
                    with open(description_file, "r", encoding="utf-8") as f:
                        description = f.read()
                    logger.info(f"Found existing description file: {description_file}")
                except Exception as e:
                    logger.error(f"Error reading existing description file: {e}")

            # If we don't have a description yet, try to extract it
            if not description:
                try:
                    description = extract_bug_description(url)
                    if description:
                        # Save extracted description to file
                        with open(description_file, "w", encoding="utf-8") as f:
                            f.write(description)
                        logger.info(f"Saved description to {description_file}")
                except Exception as e:
                    logger.error(f"Error extracting description from {url}: {e}")

            # If we have a description, extract fix commits from it and add to descriptions list
            if description:
                descriptions.append({"source": source, "url": url, "text": description})

                # First use specialized URL-based extractors if there's a URL-specific function for it
                url_specific_commits = extract_fix_commits_by_url(url, description)
                logger.info(
                    f"Extracted {len(url_specific_commits)} fix commits via extractor for {url}"
                )
                for commit_info in url_specific_commits:
                    sha = commit_info.get("sha")
                    # Prioritize entry with URL, update if new one has URL or existing one doesn't
                    if sha and (
                        sha not in extracted_fix_commits_dict or commit_info.get("url")
                    ):
                        extracted_fix_commits_dict[sha] = commit_info

                # Always try general text extraction from description as backup/supplement
                text_extracted_commits = extract_fix_commits(
                    description, repo_owner, repo_name
                )
                if text_extracted_commits:
                    logger.info(
                        f"Extracted {len(text_extracted_commits)} fix commits from description text for {url}"
                    )
                    for commit_info in text_extracted_commits:
                        sha = commit_info.get("sha")
                        # Prioritize entry with URL
                        if sha and (
                            sha not in extracted_fix_commits_dict
                            or commit_info.get("url")
                        ):
                            extracted_fix_commits_dict[sha] = commit_info

    # Add descriptions to the entry
    if descriptions:
        entry["bug_descriptions"] = descriptions
        logger.info(f"Added {len(descriptions)} description(s) to entry {bug_id}")

    # If we have any fixed commits and at least one of them has a URL,
    # update entry["fixed_commit"] with it
    fixed_commits_dict: Dict[str, Dict[str, Optional[str]]] = {}

    # Start with the OSV fixed commit if available
    if original_fixed_commit_sha and is_osv_id(bug_id):
        sha = original_fixed_commit_sha
        # Construct URL if possible
        url = None
        if repo_owner and repo_name:
            url = generate_default_github_url(repo_owner, repo_name, sha)

        fixed_commits_dict[sha] = {"sha": sha, "url": url}
        logger.info(f"Added OSV fixed commit to fixed_commits: {sha}")

    # Add extracted commits
    extracted_commits_list = list(extracted_fix_commits_dict.values())
    if extracted_commits_list:
        for commit_info in extracted_commits_list:
            sha = commit_info.get("sha")
            # Add if not present, or update if the new entry has a URL and the existing one doesn't
            if sha and (sha not in fixed_commits_dict or commit_info.get("url")):
                fixed_commits_dict[sha] = commit_info

        entry["fixed_commits"] = extracted_commits_list
        logger.info(
            f"Added {len(extracted_commits_list)} extracted fix commits to entry {bug_id}"
        )

    return entry


def normalize_repo_url(url: str) -> str:
    """
    Normalize a repository URL to a standard format for comparison.

    This handles various edge cases like:
    - URLs ending with .git
    - Different URL formats (HTTPS, SSH, Git protocol)
    - Case sensitivity

    Args:
        url: The repository URL to normalize

    Returns:
        str: The normalized URL for comparison
    """
    if not url:
        return ""

    # Convert to lowercase for case-insensitive comparison
    url = url.lower()

    # Remove trailing .git if present
    if url.endswith(".git"):
        url = url[:-4]

    # Handle SSH URLs (git@github.com:owner/repo)
    if url.startswith("git@"):
        # Convert to https format
        parts = url.split("@", 1)[1].split(":", 1)
        if len(parts) == 2:
            domain, path = parts
            url = f"https://{domain}/{path}"

    # Handle Git protocol URLs (git://github.com/owner/repo)
    elif url.startswith("git://"):
        # Convert to https format
        parts = url[6:].split("/", 1)
        if len(parts) == 2:
            domain, path = parts
            url = f"https://{domain}/{path}"

    # Remove trailing slashes
    url = url.rstrip("/")

    # Remove http:// or https:// for more flexible matching
    for prefix in ["https://", "http://"]:
        if url.startswith(prefix):
            url = url[len(prefix) :]
            break

    return url


def process_entries(
    input_file: str,
    output_file: str,
    descriptions_dir: str,
    max_entries: Optional[int] = None,
    vuln_type: str = "ALL",
    languages: Optional[str] = None,
    blacklist: Optional[str] = None,
    whitelist: Optional[str] = None,
    oss_fuzz_config: Optional[str] = None,
    fixed_only: bool = False,
) -> None:
    """Process all entries in the input JSONL file and extract bug descriptions.

    Args:
        input_file: Path to the input JSONL file
        output_file: Path to save the output JSONL file
        descriptions_dir: Directory to store extracted descriptions
        max_entries: Maximum number of entries to process (for testing)
        vuln_type: Type of vulnerabilities to process ("CVE", "OSV", or "ALL")
        languages: Comma-separated list of programming languages to filter by
        blacklist: Comma-separated list of repository names to exclude
        whitelist: Comma-separated list of repository names to include
        oss_fuzz_config: Path to OSS-Fuzz projects configuration file
        fixed_only: Only include entries with a non-empty fixed commit
    """
    # Start timing
    # start_time = time.time()

    input_path = Path(input_file)
    output_path = Path(output_file)
    descriptions_path = Path(descriptions_dir)

    # Display welcome message
    console.print(
        Panel.fit(
            "[bold blue]Bug Description Extractor[/bold blue] - Extracting bug descriptions from reference URLs in vulnerability entries",
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

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Ensure descriptions directory exists
    descriptions_path.mkdir(parents=True, exist_ok=True)

    # Read input entries
    entries = []
    with open(input_path, "r") as f:
        for line in f:
            entries.append(json.loads(line.strip()))

    # Apply max_entries limit if specified
    if max_entries is not None:
        entries = entries[:max_entries]

    # Filter entries by vulnerability type
    if vuln_type != "ALL":
        filtered_entries = []
        for entry in entries:
            bug_id = entry.get("id", "")
            if is_valid_vuln_type(bug_id, vuln_type):
                filtered_entries.append(entry)

        # Create visual representation for vulnerability type filtering
        vuln_count = len(filtered_entries)
        non_vuln_count = len(entries) - vuln_count

        table = Table(
            title=f"Vulnerability Type Filtering ({vuln_type})", border_style="yellow"
        )
        table.add_column("Type", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Status", style="magenta")

        table.add_row(vuln_type, str(vuln_count), "✅ Included")
        table.add_row("Other", str(non_vuln_count), "❌ Excluded")

        console.print(table)

        entries = filtered_entries
        console.print(
            f"\n[bold green]{len(entries)}[/bold green] entries kept after {vuln_type} vulnerability filtering"
        )

    # Filter entries based on fixed commit presence
    if fixed_only:
        filtered_entries = []
        for entry in entries:
            fixed_commit = entry.get("fixed", "")
            if fixed_commit:  # Check if fixed field is not empty
                filtered_entries.append(entry)

        # Create visual representation for fixed commit filtering
        has_fixed_count = len(filtered_entries)
        no_fixed_count = len(entries) - has_fixed_count

        table = Table(title="Fixed Commit Filtering", border_style="yellow")
        table.add_column("Fixed Commit Status", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Status", style="magenta")

        table.add_row("Has fixed commit", str(has_fixed_count), "✅ Included")
        table.add_row("No fixed commit", str(no_fixed_count), "❌ Excluded")

        console.print(table)

        entries = filtered_entries
        console.print(
            f"\n[bold green]{len(entries)}[/bold green] entries kept after fixed commit filtering"
        )

    # Filter entries by programming language
    if languages:
        lang_list = [lang.strip().lower() for lang in languages.split(",")]
        filtered_entries = []
        language_counts = {lang: 0 for lang in lang_list}

        for entry in entries:
            entry_lang = entry.get("language", "").lower()
            if entry_lang and entry_lang in lang_list:
                filtered_entries.append(entry)
                language_counts[entry_lang] += 1

        entries = filtered_entries

        # Create visual table for language filtering
        table = Table(title="Language Filtering Results", border_style="blue")
        table.add_column("Language", style="cyan")
        table.add_column("Entries Kept", style="green")
        table.add_column("Status", style="magenta")

        for lang, count in language_counts.items():
            if count > 0:
                table.add_row(lang, str(count), "✅ Included")
            else:
                table.add_row(lang, "0", "❌ No entries found")

        console.print(table)
        console.print(
            f"\n[bold green]{len(entries)}[/bold green] entries kept after language filtering"
        )

    # Filter entries by repository name (whitelist)
    if whitelist:
        whitelist_repos = [repo.strip().lower() for repo in whitelist.split(",")]
        filtered_entries = []
        kept_repos = set()

        for entry in entries:
            repo = entry.get("repo", "")
            if repo:
                # Extract repo name (second part after splitting by /)
                repo_parts = repo.split("/")
                if len(repo_parts) >= 2:
                    repo_name = repo_parts[1].lower()
                    if repo_name in whitelist_repos:
                        filtered_entries.append(entry)
                        kept_repos.add(repo)

        entries = filtered_entries

        # Create a visual table for whitelisted repositories
        table = Table(title="Whitelist Filtering Results", border_style="green")
        table.add_column("Repository", style="cyan", no_wrap=True)
        table.add_column("Status", style="green bold")
        table.add_column("Entries", style="magenta")

        repo_counts = {}
        for repo in kept_repos:
            if repo not in repo_counts:
                repo_counts[repo] = 0
            repo_counts[repo] += 1

        for repo_name in sorted(whitelist_repos):
            matching_repos = [
                r for r in kept_repos if r.lower().endswith(f"/{repo_name}")
            ]
            if matching_repos:
                for repo in matching_repos:
                    table.add_row(repo, "✅ Included", str(repo_counts.get(repo, 0)))
            else:
                table.add_row(f"*/{repo_name}", "❌ No matches", "0")

        console.print(table)
        console.print(
            f"\n[bold green]{len(entries)}[/bold green] entries kept after whitelist filtering"
        )

    # Filter entries by repository name (blacklist)
    if blacklist:
        blacklist_repos = [repo.strip().lower() for repo in blacklist.split(",")]
        filtered_entries = []
        excluded_repos = set()
        kept_repos = set()

        for entry in entries:
            repo = entry.get("repo", "")
            if repo:
                # Extract repo name (second part after splitting by /)
                repo_parts = repo.split("/")
                if len(repo_parts) >= 2:
                    repo_name = repo_parts[1].lower()
                    if repo_name not in blacklist_repos:
                        filtered_entries.append(entry)
                        kept_repos.add(repo)
                    else:
                        excluded_repos.add(repo)
                else:
                    # If can't extract repo name, keep the entry
                    filtered_entries.append(entry)
            else:
                # If no repo field, keep the entry
                filtered_entries.append(entry)

        entries = filtered_entries

        # Create a visual table for blacklisted repositories
        table = Table(title="Blacklist Filtering Results", border_style="red")
        table.add_column("Repository", style="cyan", no_wrap=True)
        table.add_column("Status", style="yellow")

        for repo in sorted(excluded_repos):
            table.add_row(repo, "🚫 Excluded")

        console.print(table)
        console.print(
            f"\n[bold green]{len(entries)}[/bold green] entries kept after blacklist filtering"
        )

    # Filter entries by OSS-Fuzz projects
    if oss_fuzz_config:
        # Load OSS-Fuzz projects
        oss_fuzz_projects = {}  # Store project name -> main_repo mapping

        try:
            with open(oss_fuzz_config, "r") as f:
                for line in f:
                    project_data = json.loads(line.strip())
                    if "name" in project_data and "main_repo" in project_data:
                        project_name = project_data["name"].lower()
                        main_repo = project_data["main_repo"]
                        # Store both the project name and its main repository URL
                        oss_fuzz_projects[project_name] = normalize_repo_url(main_repo)

            filtered_entries = []
            kept_repos = set()
            excluded_repos = set()
            matched_projects = {}  # For tracking which OSS-Fuzz project matched each repo

            for entry in entries:
                repo_url = entry.get("repo_url", "")
                repo = entry.get("repo", "")  # Keep this for display purposes

                if repo_url:
                    # Normalize the repo URL for comparison
                    normalized_repo_url = normalize_repo_url(repo_url)

                    # Check if this repo URL matches any OSS-Fuzz project's main repo
                    match_found = False
                    matched_project = None

                    # Direct URL matching with full path (including owner)
                    for project_name, project_repo_url in oss_fuzz_projects.items():
                        if normalized_repo_url == project_repo_url:
                            match_found = True
                            matched_project = project_name
                            break

                    # If no direct match, try partial matching but ensure we consider owner
                    if not match_found and repo:
                        # Extract full path (owner/repo) from the repo field if possible
                        repo_parts = repo.split("/")
                        if len(repo_parts) >= 2:
                            # Get owner and repo
                            owner, repo_name = (
                                repo_parts[0].lower(),
                                repo_parts[1].lower(),
                            )

                            # Try to find a match considering both owner and repo name
                            for (
                                project_name,
                                project_repo_url,
                            ) in oss_fuzz_projects.items():
                                # Extract owner/repo from the normalized project URL
                                parts = project_repo_url.split("/")
                                if len(parts) >= 2:
                                    project_owner = parts[
                                        -2
                                    ].lower()  # Second-to-last component is owner
                                    project_repo = parts[
                                        -1
                                    ].lower()  # Last component is repo name

                                    # Check if both owner and repo match
                                    if (
                                        project_owner == owner
                                        and project_repo == repo_name
                                    ):
                                        match_found = True
                                        matched_project = project_name
                                        break
                                    elif (
                                        project_name in OSV_MAPPING.keys()
                                        and repo_url == OSV_MAPPING[project_name][1]
                                    ):
                                        match_found = True
                                        matched_project = project_name
                                        break

                    if match_found:
                        filtered_entries.append(entry)
                        kept_repos.add(repo_url)
                        matched_projects[repo_url] = matched_project
                    else:
                        excluded_repos.add(repo_url)
                else:
                    # If no repo_url field, try to use repo field if available
                    if repo:
                        # Extract repo name (second part after splitting by /)
                        repo_parts = repo.split("/")
                        if len(repo_parts) >= 2:
                            owner, repo_name = (
                                repo_parts[0].lower(),
                                repo_parts[1].lower(),
                            )

                            # Try to find a match considering both owner and repo name
                            match_found = False
                            matched_project = None

                            for (
                                project_name,
                                project_repo_url,
                            ) in oss_fuzz_projects.items():
                                # Extract owner/repo from the normalized project URL
                                parts = project_repo_url.split("/")
                                if len(parts) >= 2:
                                    project_owner = parts[
                                        -2
                                    ].lower()  # Second-to-last component is owner
                                    project_repo = parts[
                                        -1
                                    ].lower()  # Last component is repo name

                                    # Check if both owner and repo match
                                    if (
                                        project_owner == owner
                                        and project_repo == repo_name
                                    ):
                                        match_found = True
                                        matched_project = project_name
                                        break

                            if match_found:
                                filtered_entries.append(entry)
                                kept_repos.add(repo)
                                matched_projects[repo] = matched_project
                            else:
                                excluded_repos.add(repo)
                        else:
                            # If can't extract repo name, skip the entry
                            excluded_repos.add("(no repo information)")
                    else:
                        # If no repo_url and no repo field, skip the entry
                        excluded_repos.add("(no repo information)")

            entries = filtered_entries

            # Create a visual table for OSS-Fuzz filtering results
            table = Table(
                title="OSS-Fuzz Projects Filtering Results", border_style="blue"
            )
            table.add_column("Repository", style="cyan", no_wrap=True)
            table.add_column("OSS-Fuzz Project", style="yellow")
            table.add_column("Match Type", style="magenta")
            table.add_column("Status", style="green bold")

            # Get counts of repositories kept
            repo_counts = {}

            for entry in filtered_entries:
                repo_url = entry.get("repo_url", "")
                repo = entry.get("repo", "")

                # Use repo_url if available, otherwise fall back to repo
                repo_key = repo_url if repo_url else repo

                if repo_key:
                    if repo_key not in repo_counts:
                        repo_counts[repo_key] = 0
                    repo_counts[repo_key] += 1

            # Show included repositories
            for repo_key in sorted(kept_repos):
                oss_fuzz_project = matched_projects.get(repo_key, "")
                # Determine match type based on whether it's a URL or a repo name
                match_type = (
                    "URL match"
                    if repo_key in [e.get("repo_url", "") for e in filtered_entries]
                    else "Name match"
                )
                status = f"✅ Included ({repo_counts[repo_key]} entries)"

                table.add_row(repo_key, oss_fuzz_project, match_type, status)

            # Show some excluded repositories (up to 10 to avoid excessive output)
            for repo in sorted(list(excluded_repos)[:10]):
                table.add_row(repo, "", "No match", "❌ Excluded")

            if len(excluded_repos) > 10:
                table.add_row(
                    f"... {len(excluded_repos) - 10} more", "", "", "❌ Excluded"
                )

            console.print(table)
            console.print(
                f"\n[bold green]{len(entries)}[/bold green] entries kept after OSS-Fuzz filtering"
            )
        except Exception as e:
            console.print(
                f"[bold red]Error loading OSS-Fuzz configuration:[/bold red] {str(e)}"
            )
            logger.exception("Failed to filter by OSS-Fuzz projects")

    console.print(f"Found [bold green]{len(entries)}[/bold green] entries to process")

    # Deduplicate entries based on id field
    deduplicated_entries = {}
    duplicate_count = 0

    for entry in entries:
        entry_id = entry.get("id", "unknown")
        if entry_id not in deduplicated_entries:
            deduplicated_entries[entry_id] = entry
        else:
            duplicate_count += 1

    entries = list(deduplicated_entries.values())

    if duplicate_count > 0:
        console.print(
            f"Removed [bold yellow]{duplicate_count}[/bold yellow] duplicate entries based on id field"
        )
    console.print(
        f"Proceeding with [bold green]{len(entries)}[/bold green] unique entries"
    )

    # Ask for confirmation before proceeding
    user_input = Confirm.ask(
        f"Will you proceed with processing {len(entries)} entries?", default=True
    )
    if not user_input:
        console.print("[bold red]Operation cancelled by user.[/bold red]")
        return

    # Extract bug descriptions
    console.print(
        "\n[bold blue]Extracting bug descriptions from references...[/bold blue]"
    )

    results = []
    entries_with_descriptions = 0
    total_descriptions = 0
    entries_with_original_fix = 0
    entries_with_extracted_fixes = 0
    total_entries_with_fixes = 0
    source_counts: Dict[str, int] = {}  # Dictionary to track the count of sources

    # Open the output file in append mode
    with open(output_path, "w") as output_file_handle:
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
            # Create the extraction progress task
            extract_task = progress.add_task(
                "[cyan]Extracting bug descriptions...", total=len(entries)
            )

            # Process each entry
            for entry in entries:
                bug_id = entry.get("id", "unknown")
                repo = entry.get("repo", "unknown")
                progress.update(
                    extract_task,
                    description=f"[cyan]Extracting descriptions for [bold]{bug_id}[/bold] from [bold]{repo}[/bold]",
                )

                # Extract descriptions
                updated_entry = extract_descriptions_for_entry(
                    entry, descriptions_path, source_counts
                )

                # Write to output file immediately after processing each entry
                output_file_handle.write(json.dumps(updated_entry) + "\n")
                output_file_handle.flush()  # Ensure the data is written immediately

                # Update statistics
                results.append(updated_entry)
                if "bug_descriptions" in updated_entry:
                    entries_with_descriptions += 1
                    total_descriptions += len(updated_entry.get("bug_descriptions", []))

                # Track fix commit statistics
                if updated_entry.get("fixed", ""):
                    entries_with_original_fix += 1

                if updated_entry.get("fixed_commits", []):
                    entries_with_extracted_fixes += 1

                if updated_entry.get("fixed_commits", []):
                    total_entries_with_fixes += 1

                # Advance the progress bar
                progress.advance(extract_task)

    # Create a summary text block instead of a table
    summary_text = ""

    summary_text += f"Processed [bold cyan]{len(results)}[/bold cyan] unique entries (after deduplication by id).\n"
    summary_text += f"Entries with descriptions: [bold green]{entries_with_descriptions}/{len(results)}[/bold green] "
    summary_text += f"([bold cyan]{entries_with_descriptions / len(results) * 100:.1f}%[/bold cyan] success rate)\n"

    if entries_with_descriptions > 0:
        summary_text += (
            f"Total descriptions: [bold green]{total_descriptions}[/bold green] "
        )
        summary_text += f"(average [bold cyan]{total_descriptions / entries_with_descriptions:.1f}[/bold cyan] per entry)\n"
    else:
        summary_text += "Total descriptions: [bold yellow]0[/bold yellow]\n"

    summary_text += f"Output saved to [bold blue]{output_path}[/bold blue]\n"
    summary_text += f"Descriptions saved to [bold blue]{descriptions_path}[/bold blue]"

    console.print(Panel.fit(summary_text, title="Summary"))

    # Display source statistics
    if source_counts:
        # Sort sources by count in descending order
        sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)

        source_table = Table(title="Source Statistics", border_style="blue")
        source_table.add_column("Source", style="cyan")
        source_table.add_column("Count", style="green")
        source_table.add_column("Percentage", style="yellow")

        total_sources = sum(source_counts.values())

        for source, count in sorted_sources:
            percentage = (count / total_sources) * 100
            source_table.add_row(source, str(count), f"{percentage:.1f}%")

        console.print(source_table)

    # Display simplified fix commit statistics
    fix_table = Table(title="Fix Commit Statistics", border_style="green")
    fix_table.add_column("Metric", style="cyan")
    fix_table.add_column("Count", style="green")
    fix_table.add_column("Percentage", style="yellow")

    # Show only the three key metrics
    fix_table.add_row(
        "Entries with original fixed commit",
        str(entries_with_original_fix),
        f"{entries_with_original_fix / len(results) * 100:.1f}%",
    )
    fix_table.add_row(
        "Entries with extracted fix commits",
        str(entries_with_extracted_fixes),
        f"{entries_with_extracted_fixes / len(results) * 100:.1f}%",
    )
    fix_table.add_row(
        "Total CVE instances with fix commits",
        str(total_entries_with_fixes),
        f"{total_entries_with_fixes / len(results) * 100:.1f}%",
    )

    console.print(fix_table)


def get_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract bug report from reference URLs in preprocessed data by `seed.py`"
    )
    parser.add_argument(
        "--input-file",
        required=True,
        help="Input JSONL file containing preprocessed data",
    )
    parser.add_argument(
        "--output-file",
        required=True,
        help="Output JSONL file path (with bug reports)",
    )
    parser.add_argument(
        "--reports-dir",
        default="output/reports",
        help="Directory to store extracted bug reports",
    )
    parser.add_argument("--log-file", default="logs/report.log", help="Log file path")
    parser.add_argument(
        "--max-entries",
        type=int,
        default=None,
        help="Maximum number of entries to process (for testing)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "--type",
        choices=["CVE", "OSV", "ALL"],
        default="ALL",
        help="Select vulnerability type (CVE, OSV, or ALL) to extract bug reports from. Default is ALL.",
    )
    parser.add_argument(
        "--lang",
        help="Filter entries by programming language (comma-separated for multiple languages)",
    )
    parser.add_argument(
        "--blacklist",
        help="Comma-separated list of repository names to exclude from processing",
    )
    parser.add_argument(
        "--whitelist",
        help="Comma-separated list of repository names to include in processing",
    )
    parser.add_argument(
        "--oss-fuzz",
        nargs="?",
        const="secb/data/oss-fuzz-projects.jsonl",
        metavar="CONFIG_PATH",
        help="Filter entries by OSS-Fuzz projects. Optional path to project list (default: secb/data/oss-fuzz-projects.jsonl)",
    )
    parser.add_argument(
        "--fixed-only",
        action="store_true",
        help="Filter entries to include only those with a non-empty fixed commit",
    )

    return parser.parse_args()


def main() -> None:
    """Main function to run the script."""
    args = get_args()

    # Configure logger
    logger.remove()  # Remove default handler
    log_path = Path(args.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger.add(args.log_file, level="INFO" if not args.verbose else "DEBUG")
    logger.add(lambda msg: console.print(f"[dim]{msg}[/dim]") if args.verbose else None)

    # Process the entries
    try:
        process_entries(
            args.input_file,
            args.output_file,
            args.reports_dir,
            args.max_entries,
            args.type,
            args.lang,
            args.blacklist,
            args.whitelist,
            args.oss_fuzz,
            args.fixed_only,
        )
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Process interrupted by user[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        logger.exception("Unhandled exception")


if __name__ == "__main__":
    main()
