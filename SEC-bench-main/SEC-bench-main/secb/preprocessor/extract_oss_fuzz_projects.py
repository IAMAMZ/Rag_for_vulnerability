#!/usr/bin/env python3
"""OSS-Fuzz Project Extractor.

This module extracts the complete list of OSS-Fuzz projects, downloads their
project.yaml configuration files, and saves the consolidated project information
in JSONL format for use in vulnerability analysis.

Features:
- Fetch complete OSS-Fuzz project list from Google's repository
- Download and parse project.yaml files for each project
- Extract repository URLs and metadata
- Save project information in structured JSONL format
- Error handling for failed downloads
- Progress tracking and logging

Usage:
    python extract_oss_fuzz_projects.py

Output format:
    {
        "name": str,           # Project name
        "source": "oss-fuzz", # Source identifier
        "main_repo": str,      # Main repository URL (if available)
        "language": str        # Primary programming language
    }
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen

import yaml  # type: ignore
from loguru import logger

from secb.preprocessor.project import get_oss_fuzz_project_list


def get_default_output_path() -> str:
    """Calculate the default output path relative to the script location."""
    # Get the directory of the current script
    script_dir = Path(os.path.dirname(os.path.abspath(__file__)))

    # Calculate the path to the data directory (sibling to collect)
    data_dir = script_dir.parent / "data"

    # Return the full path to the OSS-Fuzz projects file
    return str(data_dir / "oss-fuzz-projects.jsonl")


def download_project_yaml(project_name: str) -> Optional[Dict[str, Any]]:
    """
    Download the project.yaml file for a given OSS-Fuzz project and parse it.

    Args:
        project_name: Name of the OSS-Fuzz project

    Returns:
        Parsed YAML content as a dictionary or None if download fails
    """
    url = f"https://raw.githubusercontent.com/google/oss-fuzz/master/projects/{project_name}/project.yaml"
    req = Request(url, headers={"User-Agent": "Python-urllib"})
    try:
        with urlopen(req) as response:
            if response.status != 200:
                logger.warning(
                    f"Failed to download project.yaml for {project_name}: HTTP {response.status}"
                )
                return None
            yaml_content = response.read().decode("utf-8")
            return yaml.safe_load(yaml_content)
    except Exception as e:
        logger.warning(f"Error downloading project.yaml for {project_name}: {e}")
        return None


def save_projects_to_jsonl(projects: List[str], output_path: Path) -> None:
    """
    Save the list of OSS-Fuzz projects to a JSONL file, including main_repo URLs.

    Args:
        projects: List of project names
        output_path: Path to the output JSONL file
    """
    # Create directory if it doesn't exist
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Process each project, download yaml, and write to file
    count = 0
    success_count = 0
    with open(output_path, "w") as f:
        for project in projects:
            logger.info(f"Processing project: {project}")
            project_obj = {"name": project, "source": "oss-fuzz"}

            # Download and parse project.yaml
            yaml_content = download_project_yaml(project)
            if yaml_content:
                # Extract main_repo if available
                main_repo = yaml_content.get("main_repo")
                if main_repo:
                    project_obj["main_repo"] = main_repo
                    success_count += 1
                else:
                    logger.warning(f"No main_repo found for {project}")

                # Add any other interesting fields
                project_obj["language"] = yaml_content.get("language", "")
                # project_obj["sanitizers"] = yaml_content.get("sanitizers", [])

            f.write(json.dumps(project_obj) + "\n")
            count += 1

    logger.info(f"Saved {count} OSS-Fuzz projects to {output_path}")
    logger.info(f"Successfully extracted main_repo for {success_count} projects")


def main() -> None:
    """Main function to extract and save OSS-Fuzz project list with repository information."""
    # Get the project list
    logger.info("Fetching OSS-Fuzz project list...")
    projects = get_oss_fuzz_project_list()

    if not projects:
        logger.error("Failed to retrieve OSS-Fuzz projects.")
        return

    logger.info(f"Retrieved {len(projects)} OSS-Fuzz projects.")

    # Define the output path
    output_path = get_default_output_path()

    # Save projects to JSONL file with additional information
    save_projects_to_jsonl(projects, Path(output_path))


if __name__ == "__main__":
    main()
