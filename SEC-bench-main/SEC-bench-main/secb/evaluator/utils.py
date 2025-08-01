"""Utility functions for SEC-bench evaluator module.

This module provides utility functions for processing sanitizer reports,
extracting error information, and cleaning bug descriptions.
"""

import re
from typing import List, Optional, Tuple

# Sanitizer error message patterns for detection
SANITIZER_ERROR_PATTERNS: List[str] = [
    "ERROR: AddressSanitizer:",
    "ERROR: MemorySanitizer:",
    "WARNING: MemorySanitizer:",
    "UndefinedBehaviorSanitizer:DEADLYSIGNAL",
    "ERROR: LeakSanitizer:",
    "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior",
]

# Sanitizer report parsing patterns
SANITIZER_START_PATTERN: str = r"==\d+==(?:ERROR|WARNING): (\w+)Sanitizer:"
SANITIZER_END_PATTERN: str = r"==\d+==ABORTING"
STACK_TRACE_END_PATTERN: str = r"\s+#\d+ 0x[0-9a-f]+"

# Additional sanitizer error indicators for fallback detection
SANITIZER_INDICATORS: List[str] = [
    "AddressSanitizer",
    "LeakSanitizer",
    "UndefinedBehaviorSanitizer",
    "ThreadSanitizer",
    "MemorySanitizer",
]

# Section removal patterns for bug description cleaning
SECTION_REMOVAL_PATTERNS: List[str] = [
    r"\n\nComments:\n.*",
    r"\n\nAttachments:\n.*",
    r"\n\nCommit References:\n.*",
    r"\n\nReferences:\n.*",
    r"\n\nLinks:\n.*",
    r"\n\nAffected Packages:\n.*",
    r"\n\nIdentifiers:\n.*",
    r"\n\nCredits:\n.*",
    r"\n\nRelevant Links:\n.*",
    # Handle GitHub comment separator pattern
    r"\n\n---\n\n.*",
]


def extract_sanitizer_report(container_output: str) -> Optional[str]:
    """Extract the sanitizer report from container output using regex.

    Args:
        container_output: Container log output to process.

    Returns:
        Extracted sanitizer report or None if no report found.
    """
    if not container_output:
        return None

    # Look for complete sanitizer report with both start and end patterns
    start_match = re.search(SANITIZER_START_PATTERN, container_output)
    end_match = re.search(SANITIZER_END_PATTERN, container_output)

    if start_match and end_match:
        # Get the start and end positions of the report
        start_pos = start_match.start()
        end_pos = end_match.end()

        # Make sure end_pos comes after start_pos
        if end_pos > start_pos:
            # Extract the complete report
            return container_output[start_pos:end_pos]

    # If we have a start match but no end match, try to find the last stack trace line
    if start_match and not end_match:
        start_pos = start_match.start()
        # Find all stack trace lines
        stack_trace_matches = list(
            re.finditer(STACK_TRACE_END_PATTERN, container_output[start_pos:])
        )
        if stack_trace_matches:
            # Use the last stack trace line as the end point (plus some buffer)
            last_match = stack_trace_matches[-1]
            end_pos = (
                # Find the position after the last stack trace match
                start_pos + last_match.end()
            )
            # Find the next newline after the last stack trace match
            next_newline_pos = container_output.find("\n", end_pos)
            if next_newline_pos != -1:
                end_pos = next_newline_pos + 1  # Include the newline
            end_pos = min(end_pos, len(container_output))
            return container_output[start_pos:end_pos]

    # If we can't find a complete report, check if any sanitizer indicators exist
    if any(indicator in container_output for indicator in SANITIZER_ERROR_PATTERNS):
        # Extract context around the first indicator found
        for indicator in SANITIZER_ERROR_PATTERNS:
            if indicator in container_output:
                idx = container_output.find(indicator)
                # Get up to 1000 characters before and after the indicator
                start_idx = max(0, idx - 1000)
                end_idx = min(len(container_output), idx + 1000)
                return container_output[start_idx:end_idx]

    return None


def check_sanitizer_errors(container_output: str) -> Tuple[bool, Optional[str]]:
    """Check if container output contains sanitizer errors and extract the report.

    Args:
        container_output: Container log output to check.

    Returns:
        Tuple of (has_errors, error_report) where:
        - has_errors: True if sanitizer errors found, False otherwise
        - error_report: The extracted sanitizer report or None if no report found
    """
    sanitizer_report = extract_sanitizer_report(container_output)

    if sanitizer_report:
        # If we have a report, return it with True for has_errors
        return True, sanitizer_report

    # Fallback check for any sanitizer indicator
    # has_errors = any(
    #     indicator in container_output for indicator in SANITIZER_INDICATORS
    # )
    # return has_errors, container_output if has_errors else None
    return False, None


def extract_report_from_bug_description(bug_description: str) -> Optional[str]:
    """Extract the report content only from the bug description.

    This function removes metadata sections and comments to extract only
    the core bug report content.

    Args:
        bug_description: Raw bug description to process.

    Returns:
        Extracted report content or None if no meaningful content found.
    """
    if not bug_description or not bug_description.strip():
        return None

    # Start with the original description
    cleaned_description = bug_description

    # Remove each section pattern
    for pattern in SECTION_REMOVAL_PATTERNS:
        cleaned_description = re.sub(pattern, "", cleaned_description, flags=re.DOTALL)

    # Apply platform-specific cleaning rules
    cleaned_description = _apply_platform_specific_cleaning(cleaned_description)

    # Clean up any trailing whitespace and normalize line endings
    cleaned_description = cleaned_description.strip()

    # Return None if the cleaned description is empty or too short to be meaningful
    if not cleaned_description or len(cleaned_description.strip()) < 10:
        return None

    return cleaned_description


def _apply_platform_specific_cleaning(description: str) -> str:
    """Apply platform-specific cleaning rules to bug descriptions.

    Args:
        description: Bug description to clean.

    Returns:
        Cleaned description with platform-specific sections removed.
    """
    # For GitHub issues, keep only up to and including the main issue body
    if "Issue Body:" in description:
        # Find the issue body section and preserve it
        issue_body_match = re.search(
            r"(.*?Issue Body:\n.*?)(?=\n\n(?:Comment by|Comments:|$))",
            description,
            re.DOTALL,
        )
        if issue_body_match:
            return issue_body_match.group(1)

    # For PHP bugs, keep metadata and description but remove comments
    elif "PHP Bug ID:" in description:
        # Keep everything up to the first "Comment by" or "Comments:" section
        php_match = re.search(
            r"(.*?)(?=\n\n(?:\[Comment \d+\]|Comments:|$))",
            description,
            re.DOTALL,
        )
        if php_match:
            return php_match.group(1)

    # For Bugzilla, keep metadata and main content but remove comments
    elif "Bugzilla ID:" in description:
        # Keep everything before comments section
        bugzilla_match = re.search(
            r"(.*?)(?=\n\n(?:Comments:|$))", description, re.DOTALL
        )
        if bugzilla_match:
            return bugzilla_match.group(1)

    # For Openwall, keep everything before Links section if it exists
    elif "Openwall Report" in description:
        openwall_match = re.search(r"(.*?)(?=\n\nLinks:\n|$)", description, re.DOTALL)
        if openwall_match:
            return openwall_match.group(1)

    # For GitHub Security Advisories, keep everything before References section
    elif "Advisory ID:" in description:
        advisory_match = re.search(
            r"(.*?)(?=\n\nReferences:\n|$)", description, re.DOTALL
        )
        if advisory_match:
            return advisory_match.group(1)

    return description
