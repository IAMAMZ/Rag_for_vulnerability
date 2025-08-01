#!/usr/bin/env python3
"""SEC-bench Evaluation Instance Builder.

This module builds verified evaluation instances from processed vulnerability data.
It validates vulnerability instances, applies patches, runs exploits, and creates
Docker images ready for agent evaluation.

Features:
- Docker-based validation of vulnerability instances
- Automated patch application and verification
- Exploit execution and sanitizer detection
- Multi-threaded instance processing
- Comprehensive validation reporting
- Dataset generation for evaluation

Usage:
    python build_eval_instances.py --input-dir <instances_dir> [options]

Options:
    --input-dir PATH      Directory containing instance data
    --output-file PATH    Output file for validation results
    --dataset-output PATH Output file for dataset instances
    --force               Force rebuild of existing instances
    --ids IDS             Comma-separated list of instance IDs to process
    --num-workers N       Number of parallel workers

Output format:
    Validated instances are saved as Docker images with the naming convention:
    hwiwonlee/secb.eval.x86_64.[instance_id]
"""

import argparse
import base64
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
import multiprocessing
from functools import partial
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Tuple, TypedDict, cast

# Type ignore for datasets which lacks type stubs
import datasets  # type: ignore
import docker  # type: ignore
from jinja2 import Environment, FileSystemLoader
from loguru import logger

from secb.evaluator.utils import (
    check_sanitizer_errors,
    extract_sanitizer_report,
    extract_report_from_bug_description,
)


# Define type structures
class PhaseResultDict(TypedDict):
    success: bool
    output: str
    error: str
    command: str
    skipped: bool


class PatchPhaseResultDict(TypedDict):
    patch_success: bool
    build_success: bool
    repro_success: bool
    output: str
    error: str
    patch_command: str
    build_command: str
    repro_command: str
    skipped: bool


class ValidationResultDict(TypedDict):
    validation_success: bool
    build_phase: PhaseResultDict
    exploit_phase: PhaseResultDict
    patch_phase: PatchPhaseResultDict
    exit_code: Optional[int]


SECB_EVAL_BASE_IMAGE = "hwiwonlee/secb.eval.base:latest"
TO_SKIP_IDS = [
    "libredwg.cve-2020-21813",
    "mruby.cve-2022-1071",
    "memcached.cve-2021-37519",
    "oniguruma.cve-2017-9225",
    "imagemagick.cve-2019-13454",
]

BUILD_COMMAND = "secb build"
REPRO_COMMAND = "secb repro"
PATCH_COMMAND = "secb patch"

REPRO_TIMEOUT = 15


def run_commands_in_session(
    client,
    image_id: str,
    commands: List[str],
    workdir: Optional[str] = None,
    stop_on_failure: bool = True,
) -> List[Tuple[str, bool, str, str]]:
    """Run multiple commands in the same container session.

    Args:
        client: Docker client
        image_id: Docker image ID
        commands: List of commands to run sequentially
        workdir: Working directory in the container
        stop_on_failure: Whether to stop running commands after a failure

    Returns:
        List of tuples (command, success, error, logs) for each command run
        For REPRO_COMMAND:
          - Before patch: success=True means sanitizer errors WERE found
          - After patch: success=True means NO sanitizer errors were found
        For other commands:
          - success=True means command exited with code 0
          - success=False means command failed
    """
    is_patched = False
    container = None
    results = []

    try:
        # Create a long-running container with a shell that stays alive
        container_params = {
            "image": image_id,
            "command": "sleep 1200",  # Keep container alive for 20 minutes
            "detach": True,
            "tty": True,
        }

        if workdir:
            container_params["working_dir"] = workdir

        # Start the container
        container = client.containers.run(**container_params)
        logger.info(f"Started session container with ID: {container.id[:12]}")

        # Run each command in the same container
        for cmd in commands:
            try:
                if REPRO_COMMAND in cmd:
                    cmd = f"timeout {REPRO_TIMEOUT} {cmd}"

                logger.info(f"Running command in session: {cmd}")

                exec_result = container.exec_run(["bash", "-c", cmd], workdir=workdir)

                if PATCH_COMMAND in cmd:
                    is_patched = True

                # Get command output
                exit_code = exec_result.exit_code
                tmp_output = exec_result.output.decode("utf-8", errors="replace")
                output = (
                    "[...TRUNCATED...] " + tmp_output[-4096:]
                    if len(tmp_output) > 4096
                    else tmp_output
                )

                # For PoC triggering command (REPRO_COMMAND), check for sanitizer patterns
                if REPRO_COMMAND in cmd:
                    has_errors, sanitizer_report = check_sanitizer_errors(tmp_output)
                    logger.info(f"Exit code: {exit_code}, has_errors: {has_errors}")

                    # Handle timeout case (exit_code 124)
                    if exit_code == 124:
                        # For timeout, always consider it a failure regardless of patch status
                        success = False
                        error = f"Command timed out after {REPRO_TIMEOUT} seconds"
                    else:
                        # Normal case - follows original logic
                        # For PoC command, success is FINDING sanitizer errors
                        # We ignore exit code entirely here - focus only on sanitizer reports
                        # For unpatched version: success = has_errors (True if errors found)
                        # For patched version: success = not has_errors (True if no errors found)
                        success = has_errors if not is_patched else not has_errors
                        error = (
                            str(sanitizer_report)
                            if sanitizer_report is not None and has_errors
                            else f"No sanitizer errors found. Exit code: {exit_code}"
                        )

                    # Log exit code for debugging but don't use it for success determination
                    logger.debug(
                        f"REPRO_COMMAND exit code: {exit_code}, has_errors: {has_errors}"
                    )
                else:
                    # For other commands (build, patch), use exit code
                    success = exit_code == 0
                    error = "" if success else f"Exit code: {exit_code}"

                results.append((cmd, success, error, output))

                # Log the result
                if success:
                    logger.info(f"Command succeeded: {cmd}")
                else:
                    logger.warning(f"Command failed: {cmd}")
                    if stop_on_failure:
                        logger.info("Stopping command execution due to failure")
                        break

            except Exception as e:
                error_msg = f"Error executing command {cmd}: {str(e)}"
                logger.error(error_msg)
                results.append((cmd, False, error_msg, ""))
                if stop_on_failure:
                    break

        return results

    finally:
        # Cleanup container
        if container:
            try:
                logger.info(f"Stopping and removing container {container.id[:12]}")
                container.stop()
                container.remove(force=True)
            except Exception as e:
                logger.error(f"Error cleaning up container: {e}")


def explore_output_json(input_dir: str) -> Dict[str, str]:
    """
    Find output.json files, group by grandparent directory, and identify the newest
    timestamp subdirectory for each group.

    Args:
        input_dir: The root directory to search for output.json files.
                   Expects structure like grandparent_dir/timestamp_dir/output.json.

    Returns:
        A dictionary mapping unique grandparent directory names to their associated
        newest timestamp subdirectory name.
    """
    grandparent_latest_timestamp: Dict[str, str] = {}

    # Find all output.json files recursively
    output_files = glob.glob(os.path.join(input_dir, "**/output.json"), recursive=True)

    for file_path in output_files:
        try:
            parent_path = os.path.dirname(file_path)
            timestamp_dir = os.path.basename(parent_path)

            grandparent_path = os.path.dirname(parent_path)
            grandparent_dir = os.path.basename(grandparent_path)

            # Skip if grandparent_dir is empty (e.g., output.json is directly under input_dir)
            if not grandparent_dir:
                continue

            # Check if this grandparent is already known
            if grandparent_dir in grandparent_latest_timestamp:
                # If the current timestamp is newer, update it
                if timestamp_dir > grandparent_latest_timestamp[grandparent_dir]:
                    grandparent_latest_timestamp[grandparent_dir] = timestamp_dir
            else:
                # First time seeing this grandparent, store its timestamp
                grandparent_latest_timestamp[grandparent_dir] = timestamp_dir

        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")

    # Return the dictionary mapping grandparents to their latest timestamp dir
    return grandparent_latest_timestamp


def build_eval_base() -> bool:
    """
    Build the base evaluation image if it doesn't exist.

    Returns:
        bool: True if the base image exists or was successfully built, False otherwise.
    """
    logger.info("Checking if base image exists...")
    cmd = ["docker", "image", "inspect", SECB_EVAL_BASE_IMAGE]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode == 0:
        logger.info("Base image already exists, skipping build.")
        return True

    logger.info("Base image not found, building it...")

    # Setup Jinja2 environment for the template
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("Dockerfile.eval.base.j2")

    # Render the template with the base image
    dockerfile_content = template.render(
        base_image="gcr.io/oss-fuzz-base/base-builder:latest"
    )

    # Create a temporary directory for building
    with tempfile.TemporaryDirectory(prefix="secb-eval-") as temp_dir:
        dockerfile_path = os.path.join(temp_dir, "Dockerfile")

        # Write the rendered Dockerfile
        with open(dockerfile_path, "w") as f:
            f.write(dockerfile_content)

        # Build the Docker image
        cmd = ["docker", "build", "-t", "hwiwonlee/secb.eval.base:latest", temp_dir]
        logger.info(f"Building base image with command: {' '.join(cmd)}")

        build_process = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        if build_process.returncode == 0:
            logger.info("Base image built successfully.")
            return True
        else:
            logger.error(f"Failed to build base image: {build_process.stderr}")
            return False


def replace_base_commit_hash(dockerfile_content: str, base_commit_hash: str) -> str:
    """Replace git checkout commit hash in dockerfile with a new hash.

    Args:
        dockerfile_content: Original dockerfile content
        base_commit_hash: New commit hash to use

    Returns:
        Updated dockerfile content
    """
    if not base_commit_hash:
        return dockerfile_content

    try:
        # Handle both 'git -C repo checkout' and 'git checkout' patterns
        # First pattern: git -C repo checkout hash
        pattern1 = r"(git\s+-C\s+\S+\s+checkout\s+)([0-9a-f]+)"
        # Second pattern: git checkout hash
        pattern2 = r"(git\s+checkout\s+)([0-9a-f]+)"

        # Use a function for replacement to avoid backreference issues
        def replace_hash(match):
            return match.group(1) + base_commit_hash

        # First try the 'git -C repo checkout' pattern
        updated_content = re.sub(pattern1, replace_hash, dockerfile_content)

        # If no changes were made, try the regular 'git checkout' pattern
        if updated_content == dockerfile_content:
            updated_content = re.sub(pattern2, replace_hash, dockerfile_content)

        # Check if any replacement was made
        if updated_content != dockerfile_content:
            logger.debug(f"Successfully replaced commit hash with: {base_commit_hash}")
            return updated_content

        # If no regex matches, return original content
        # logger.info(
        #     f"No git checkout patterns found to replace hash, returning original dockerfile"
        # )
        return dockerfile_content

    except Exception as e:
        logger.error(f"Error replacing commit hash with regex: {e}")
        logger.debug(f"Problem base_commit_hash: {repr(base_commit_hash)}")
        return dockerfile_content


def remove_from_command(dockerfile_content: str) -> str:
    """Remove FROM command from dockerfile content.

    Args:
        dockerfile_content: Original dockerfile content

    Returns:
        Dockerfile content with FROM commands removed
    """
    # Split by lines and filter out FROM commands
    lines = dockerfile_content.split("\n")
    filtered_lines = [line for line in lines if not line.strip().startswith("FROM ")]
    return "\n".join(filtered_lines)


def clean_git_repo_commits(dockerfile_content: str) -> str:
    """
    Transforms a 'RUN git clone <url> <dir>' and a subsequent 'RUN git -C <dir> checkout <hash>'
    sequence into a series of commands. These commands initialize a new Git repository
    in <dir>, fetch only the specific <hash> from <url> with a depth of 1, and then
    check out this commit detachedly using FETCH_HEAD. This approach creates a minimal
    'micro-repo' containing precisely the required commit, which can be more efficient
    than cloning, even shallowly.

    Example:
    Input:
    RUN git clone https://github.com/mruby/mruby mruby
    RUN git -C mruby checkout 55b526167b2d52d113f013b6f0c14ff9aa64c1a1

    Output:
    # ---- create micro-repo with just that commit ----
    RUN git init mruby \
     && git -C mruby fetch --depth 1 https://github.com/mruby/mruby 55b526167b2d52d113f013b6f0c14ff9aa64c1a1 \
     && git -C mruby checkout --detach FETCH_HEAD
    """
    # Pattern to find the clone and checkout sequence on consecutive logical lines.
    # Group 1: The full "RUN git clone <url> <dir>" line.
    # Group 2: The <url>.
    # Group 3: The <dir> from the clone command.
    # Group 4: The full "RUN git -C <dir> checkout <hash>" line.
    # Group 5: The <hash> from the checkout command.
    # The \3 backreference ensures the directory in "git -C <dir>" matches the one from "git clone ... <dir>".
    # re.MULTILINE makes ^ and $ match start/end of each line.
    # re.IGNORECASE makes "git" match "Git", "GIT", etc. and commit hashes.
    pattern = re.compile(
        r"^(RUN git clone\s+(https?://[^\s]+)\s+([^\s\n]+))\s*\n"  # clone line
        r"^(RUN git -C\s+\3\s+checkout\s+([0-9a-fA-F]{7,40}))\s*$",  # checkout line, using \3 for dir match
        re.MULTILINE | re.IGNORECASE,
    )

    # Replacement template:
    # # ---- create micro-repo with just that commit ----
    # RUN git init <dir> \
    #  && git -C <dir> fetch --depth 1 <url> <hash> \
    #  && git -C <dir> checkout --detach FETCH_HEAD
    # \2 is repo_url, \3 is target_dir, \5 is commit_hash.
    replacement_template = (
        r"RUN git init \3 \\\n"
        r" && git -C \3 fetch --depth 1 \2 \5 \\\n"
        r" && git -C \3 checkout --detach FETCH_HEAD"
    )

    updated_content, num_subs = pattern.subn(replacement_template, dockerfile_content)
    if num_subs > 0:
        logger.debug(
            f"Transformed {num_subs} git clone/checkout pair(s) into micro-repo fetch sequences."
        )

    return updated_content


def cleanup_and_commit_image(
    client, image_name: str, tag_type: str = "patch"
) -> Tuple[bool, Optional[str]]:
    """
    Prepare and commit the Docker image with a specific tag based on tag_type.

    Different tag types have different cleanup behaviors:
    - "latest": Keep all files, don't remove anything
    - "patch": Remove the patch file (model_patch.diff)
    - "poc": Remove both patch file and all PoC files under /testcase

    Args:
        client: Docker client
        image_name: Name of the Docker image to clean up
        tag_type: Type of tag to create ("latest", "patch", or "poc")

    Returns:
        Tuple[bool, Optional[str]]: (success, patch_content)
            - success: True if cleanup and commit were successful, False otherwise
            - patch_content: Content of model_patch.diff or None if not found/applicable
    """
    container = None
    patch_content = None
    try:
        logger.info(f"Preparing image {image_name} for {tag_type} tag")

        # Get repository and tag from image_name
        if ":" in image_name:
            # Handle case where image name has a tag with colon
            repository, _ = image_name.rsplit(":", 1)
        else:
            # Default to latest tag if no tag specified
            repository = image_name

        # Create a container with a longer-running command to ensure we have time to work with it
        container = client.containers.run(
            image=image_name,
            command="sleep 30",
            detach=True,
            remove=False,
        )

        # Wait a moment to ensure the container is fully started
        time.sleep(2)

        # Refresh container info to make sure we have current state
        container.reload()

        # Verify the container is running
        if container.status != "running":
            logger.error(f"Container status is '{container.status}', not 'running'")
            return False, None

        # Extract patch content if needed for "patch" or "poc" tag types
        if tag_type in ["patch", "poc"]:
            try:
                # Get the file contents using get_archive
                bits, stat = container.get_archive("/testcase/model_patch.diff")

                # Process the tar stream to extract the file content
                with tempfile.TemporaryDirectory() as tmp_dir:
                    temp_tar_path = os.path.join(tmp_dir, "patch.tar")
                    with open(temp_tar_path, "wb") as f:
                        for chunk in bits:
                            f.write(chunk)

                    # Extract the tar file
                    subprocess.run(["tar", "-xf", temp_tar_path, "-C", tmp_dir])

                    # Get the basename of the extracted file
                    model_patch_filename = os.path.basename(
                        "/testcase/model_patch.diff"
                    )

                    # Read the extracted file
                    extracted_file_path = os.path.join(tmp_dir, model_patch_filename)
                    with open(extracted_file_path, "r") as f:
                        patch_content = f.read()

                logger.info(
                    f"Successfully extracted model_patch.diff from image {image_name}"
                )
            except Exception as e:
                logger.warning(f"Could not extract model_patch.diff: {str(e)}")
                # Continue with cleanup operations even if extraction failed

        # Perform cleanup operations based on tag_type
        if tag_type == "latest":
            # For "latest" tag, don't remove anything
            logger.info(f"Skipping cleanup for 'latest' tag on {image_name}")
        elif tag_type == "patch":
            # For "patch" tag, remove model_patch.diff
            exec_result = container.exec_run(
                "sh -c 'if [ -f /testcase/model_patch.diff ]; then rm -rf /testcase/model_patch.diff; fi'"
            )
            if exec_result.exit_code != 0:
                logger.error(
                    f"Failed to remove model_patch.diff: exit code {exec_result.exit_code}"
                )
                return False, patch_content
            logger.info(f"Successfully removed model_patch.diff for 'patch' tag")
        elif tag_type == "poc":
            # For "poc" tag, remove all files under /testcase except certain configuration files
            exec_result = container.exec_run(
                "sh -c '"
                "if [ -d /testcase ]; then "
                '  find /testcase -type f -not -name "base_commit_hash" -not -name "repo_changes.diff" | xargs rm -f; '
                "fi"
                "'"
            )
            if exec_result.exit_code != 0:
                logger.error(
                    f"Failed to clean /testcase for 'poc' tag: exit code {exec_result.exit_code}"
                )
                return False, patch_content
            logger.info(f"Successfully cleaned /testcase directory for 'poc' tag")
        else:
            logger.warning(f"Unknown tag_type '{tag_type}', skipping cleanup")

        # Create the appropriate tag
        new_tag = tag_type
        logger.info(f"Committing with repository={repository}, tag={new_tag}")

        # Commit the container changes back to the image
        container.commit(repository=repository, tag=new_tag)
        logger.info(f"Successfully committed image {repository}:{new_tag}")

        return True, patch_content

    except Exception as e:
        logger.error(f"Error preparing image {image_name} for {tag_type} tag: {str(e)}")
        return False, patch_content

    finally:
        # Clean up the container
        if container:
            try:
                if hasattr(container, "status") and container.status == "running":
                    container.stop()
                container.remove(force=True)
            except Exception as e:
                logger.error(f"Error removing temporary container: {str(e)}")


def reformat_helper_script(secb_sh: str) -> str:
    """
    Reformat the helper script by replacing specific functions with improved versions.

    Args:
        secb_sh: The content of the secb.sh helper script

    Returns:
        The reformatted script content
    """
    # Improved build() function that filters warnings and handles errors better
    improved_build_function = """
build() {
    echo "BUILDING THE PROJECT..."
    
    # Handle git sub-modules
    if [[ -f .gitmodules || -f .gitmodule ]]; then
        echo "Detected git sub-modules - initialising/updating..."
        git submodule update --init --recursive
    else
        echo "No git sub-modules found - skipping update."
    fi
    
    # Check for repo_changes.diff and apply if it exists and hasn't been applied yet
    if [[ -f /testcase/repo_changes.diff ]]; then
        # Check if the patch has already been applied to avoid re-applying
        if ! git apply --check /testcase/repo_changes.diff &>/dev/null; then
            echo "Repository changes already applied or cannot be applied cleanly. Proceeding with build."
        else
            echo "Applying repository changes from repo_changes.diff..."
            git apply /testcase/repo_changes.diff || echo "Warning: Could not apply repo_changes.diff cleanly. Proceeding anyway."
        fi
    fi
    
    # stdout: /dev/null
    # stderr: grep filters out "warning:" and lets everything else through
    if /usr/local/bin/compile \\
         1>/dev/null \\
         2> >(grep -Fv --line-buffered -e "warning:" -e "SyntaxWarning:" -e "WARNING:" >&2); then
        echo "BUILD COMPLETED SUCCESSFULLY!"
    else
        echo "BUILD FAILED!"
        exit 1
    fi
}
"""

    # Improved patch() function that handles repository changes before applying model patch
    improved_patch_function = """
patch() {
    echo "PATCHING THE PROJECT..."
    CD_COMMAND_PLACEHOLDER
    
    # Check for repo_changes.diff and apply if it exists and hasn't been applied yet
    if [[ -f /testcase/repo_changes.diff ]]; then
        # Check if the patch has already been applied to avoid re-applying
        if ! git apply --check /testcase/repo_changes.diff &>/dev/null; then
            echo "Repository changes already applied or cannot be applied cleanly. Proceeding with patch."
        else
            echo "Applying repository changes from repo_changes.diff..."
            git apply /testcase/repo_changes.diff || echo "Warning: Could not apply repo_changes.diff cleanly. Proceeding anyway."
        fi
    fi
    
    if git apply /testcase/model_patch.diff; then
        echo "PATCH APPLIED SUCCESSFULLY!"
    else
        echo "PATCH APPLICATION FAILED!"
        exit 1
    fi
}
"""

    # Regex pattern to match the build() function
    # This pattern matches:
    # 1. The function name "build()"
    # 2. The opening brace "{"
    # 3. All content until the closing brace
    # 4. The closing brace "}"
    build_pattern = r"build\(\)\s*{[^}]*}"

    # Replace the build() function with the improved version
    reformatted_script = re.sub(build_pattern, improved_build_function.strip(), secb_sh)

    # Regex pattern to match the patch() function
    patch_pattern = r"patch\(\)\s*{[^}]*}"

    # Find the patch function in the original script
    patch_match = re.search(patch_pattern, secb_sh)

    if patch_match:
        original_patch_function = patch_match.group(0)

        # Extract the cd command if it exists
        cd_command_match = re.search(r"cd\s+[^\n;]+", original_patch_function)
        cd_command = cd_command_match.group(0) if cd_command_match else ""

        # Replace the placeholder in the improved patch function with the extracted cd command
        patch_function_with_cd = improved_patch_function.replace(
            "CD_COMMAND_PLACEHOLDER", cd_command
        )

        # Replace the original patch function with the improved one
        reformatted_script = re.sub(
            patch_pattern, patch_function_with_cd.strip(), reformatted_script
        )

        logger.debug("Reformatted secb script to use improved patch() function")

    # Log the replacement
    logger.debug("Reformatted secb script to use improved build() function")

    return reformatted_script


def reformat_build_sh(build_sh: str) -> str:
    """
    Reformat the build.sh script by replacing specific patterns with improved versions.

    Args:
        build_sh: The content of the build.sh script

    Returns:
        The reformatted script content
    """
    # List of (pattern, replacement) pairs for safer build script commands
    replacements = [
        # Handle undefined environment variables with default empty values
        (r'export LDFLAGS="(\$LDFLAGS)', r'export LDFLAGS="${LDFLAGS:-}'),
        (r'export CFLAGS="(\$CFLAGS)', r'export CFLAGS="${CFLAGS:-}'),
        (r'export CXXFLAGS="(\$CXXFLAGS)', r'export CXXFLAGS="${CXXFLAGS:-}'),
        # (r'export CPPFLAGS="(\$CPPFLAGS)', r'export CPPFLAGS="${CPPFLAGS:-}'),
        # # Fix command chaining that might fail
        # (r"(git clone .+) && cd", r'\1 && [ -d "$$(basename \1)" ] && cd'),
        # # Improve directory creation
        # (r"mkdir ([^-])", r"mkdir -p \1"),
        # # Safer path handling
        # (r'cd ([^/"\'][^ ]+)', r'cd "\1"'),
        # # Fix common typos and issues
        # (r"make clean all", r"make clean && make all"),
        # (r"autoreconf", r"autoreconf -fi"),
        # Handle case where Makefile doesn't include clean target
        (
            r"\bmake\s+clean\b",
            r'make -n clean 2>/dev/null && make clean || echo "No clean target available, skipping clean"',
        ),
    ]

    reformatted_script = build_sh

    # Apply each replacement pattern
    for pattern, replacement in replacements:
        reformatted_script = re.sub(pattern, replacement, reformatted_script)

    logger.debug("Reformatted build.sh script with safety improvements")

    return reformatted_script


def process_dataset_instance(
    instance: Dict[str, Any],
    output_data: Dict[str, Any],
    validation_result: Optional[Dict[str, Any]] = None,
    patch_content: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Process a dataset instance by combining fields from the original dataset and output data.

    Args:
        instance: The original dataset instance
        output_data: Data from output.json
        validation_result: Results from image validation, if available
        patch_content: Content of model_patch.diff to use instead of output_data patch

    Returns:
        A new instance with the required fields
    """
    # Extract fields from the original dataset
    new_instance = {
        "instance_id": instance["instance_id"],
        "repo": instance["repo"],
        "project_name": instance["project_name"],
        "lang": instance["lang"],
        "work_dir": instance["work_dir"],
        "sanitizer": instance["sanitizer"],
        "bug_description": instance["bug_description"],
    }

    # Extract fields from output_data
    base_commit_hash = output_data.get("result", {}).get("base_commit_hash", "")
    build_sh = output_data.get("result", {}).get("build_sh", "")
    secb_sh = output_data.get("result", {}).get("secb_sh", "")
    dockerfile = output_data.get("result", {}).get("dockerfile", instance["dockerfile"])

    # Add fields to the new instance
    new_instance["base_commit"] = base_commit_hash
    new_instance["build_sh"] = build_sh
    new_instance["secb_sh"] = secb_sh
    new_instance["dockerfile"] = dockerfile

    # Use patch_content if provided, otherwise fall back to output_data patch
    if patch_content is not None:
        new_instance["patch"] = patch_content
        logger.info(
            f"Using extracted model_patch.diff for instance {instance['instance_id']}"
        )
    else:
        # Fall back to the patch from output_data if available
        patch = output_data.get("result", {}).get("patch", "")
        new_instance["patch"] = patch
        logger.info(
            f"Using patch from output_data for instance {instance['instance_id']}"
        )

    # Add exit code if validation result is available
    if validation_result and "exit_code" in validation_result:
        new_instance["exit_code"] = validation_result["exit_code"]

    # Extract sanitizer report
    sanitizer_report = extract_sanitizer_report(new_instance["bug_description"])
    new_instance["sanitizer_report"] = sanitizer_report

    # Extract bug report
    bug_report = extract_report_from_bug_description(new_instance["bug_description"])
    new_instance["bug_report"] = bug_report

    return new_instance


def process_instance_worker(
    instance,
    latest_outputs,
    input_dir,
    result_file,
    dataset_output_file,
    client,
    force,
    template_dir,
):
    """
    Worker function that processes a single instance in a separate process.
    """
    # Initialize Docker client if not provided
    if client is None:
        client = docker.from_env()

    instance_id = instance["instance_id"]

    # Skip instances in TO_SKIP_IDS
    if instance_id in TO_SKIP_IDS:
        logger.info(f"Skipping instance {instance_id} as it is in TO_SKIP_IDS")
        return

    # Define image name
    image_name = f"hwiwonlee/secb.eval.x86_64.{instance_id}"

    # Check if image already exists
    try:
        client.images.get(image_name)
        if not force:
            logger.info(
                f"Image {image_name} already exists for instance {instance_id}, skipping. Use --force to rebuild."
            )
            return
        else:
            logger.info(
                f"Image {image_name} already exists for instance {instance_id}, but force rebuild is enabled."
            )
    except docker.errors.ImageNotFound:
        # Image does not exist, proceed with build
        pass
    except Exception as e:
        logger.error(
            f"Error checking for image {image_name} for instance {instance_id}: {e}"
        )
        return

    # Check if we have output data for this instance
    if instance_id not in latest_outputs:
        logger.debug(f"No output data found for instance {instance_id}, skipping.")
        return

    timestamp_dir = latest_outputs[instance_id]
    output_json_path = os.path.join(
        input_dir, instance_id, timestamp_dir, "output.json"
    )

    try:
        # Load output.json data
        with open(output_json_path, "r") as f:
            output_data = json.load(f)

        # Extract build results
        builder_success = (
            output_data.get("result", {})
            .get("execution", {})
            .get("builder", {})
            .get("success", False)
        )
        exploiter_success = (
            output_data.get("result", {})
            .get("execution", {})
            .get("exploiter", {})
            .get("success", False)
        )
        fixer_success = (
            output_data.get("result", {})
            .get("execution", {})
            .get("fixer", {})
            .get("success", False)
        )

        # Only proceed if all agents were successful
        if not (builder_success and exploiter_success and fixer_success):
            logger.warning(
                f"Instance {instance_id} did not pass all tests (builder: {builder_success}, exploiter: {exploiter_success}, fixer: {fixer_success}). Skipping."
            )
            return

        # Process the instance for the dataset if dataset_output_file is specified
        if dataset_output_file:
            # Process the dataset instance but don't save it yet - wait for validation
            dataset_instance = process_dataset_instance(instance, output_data)

        # Extract data needed for Docker build
        build_sh = output_data.get("result", {}).get("build_sh", "")
        secb_sh = output_data.get("result", {}).get("secb_sh", "")

        # Reformat the helper script to use improved functions
        secb_sh = reformat_helper_script(secb_sh)
        build_sh = reformat_build_sh(build_sh)

        env_vars = output_data.get("result", {}).get("env", {})
        artifacts = output_data.get("result", {}).get("artifacts", {})
        base_commit_hash = output_data.get("result", {}).get("base_commit_hash", "")
        repo_changes = output_data.get("result", {}).get("repo_changes", "")
        patch = output_data.get("result", {}).get("patch", "")

        # Extract instance-specific data
        project_name = instance["project_name"]
        lang = instance["lang"]
        work_dir = instance["work_dir"]
        sanitizer = instance["sanitizer"]
        dockerfile_content = instance["dockerfile"]

        assert base_commit_hash, "Base commit hash is required"

        # Replace commit hash in dockerfile if necessary
        dockerfile_content = replace_base_commit_hash(
            dockerfile_content, base_commit_hash
        )

        # Remove any FROM commands from dockerfile content
        dockerfile_content = remove_from_command(dockerfile_content)

        # Clean git clone and checkout commands
        # dockerfile_content = clean_git_repo_commits(dockerfile_content)

        # Setup Jinja2 environment for the template
        env = Environment(loader=FileSystemLoader(template_dir))
        dockerfile_template = env.get_template("Dockerfile.eval.instance.j2")

        # Create a temporary directory for building
        with tempfile.TemporaryDirectory(prefix="secb-eval-") as temp_dir:
            # Save build.sh
            with open(os.path.join(temp_dir, "build.sh"), "w") as f:
                f.write(build_sh)

            # Save secb script
            with open(os.path.join(temp_dir, "secb"), "w") as f:
                f.write(secb_sh)

            # Create testcase directory
            testcase_dir = os.path.join(temp_dir, "testcase")
            os.makedirs(testcase_dir, exist_ok=True)

            # Check if packages.txt exists in the artifacts
            packages_to_install = []
            if "packages.txt" in artifacts:
                logger.info(f"Found packages.txt in artifacts for {instance_id}")
                # Decode the base64 content
                packages_content = base64.b64decode(artifacts["packages.txt"]).decode(
                    "utf-8"
                )
                # Parse the file content line by line
                packages_to_install = [
                    pkg.strip() for pkg in packages_content.splitlines() if pkg.strip()
                ]
                # Save the packages.txt file
                with open(os.path.join(testcase_dir, "packages.txt"), "w") as f:
                    f.write(packages_content)

            # Save POC files
            for file_name, content_b64 in artifacts.items():
                # Skip files with null content
                if not content_b64:
                    logger.debug(f"Skipping file {file_name} with null content")
                    continue

                file_path = os.path.join(testcase_dir, file_name)
                # Ensure the directory exists for nested paths
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                try:
                    # Remove any whitespace from base64 string that might have been added
                    clean_b64 = (
                        content_b64.replace("\n", "").replace("\r", "").replace(" ", "")
                    )
                    with open(file_path, "wb") as f:
                        binary_file = cast(BinaryIO, f)
                        binary_file.write(base64.b64decode(clean_b64))

                    # Verify file integrity by checking if we get the same base64 content back
                    if file_name not in [
                        "packages.txt",
                        "base_commit_hash",
                        "model_patch.diff",
                        "repo_changes.diff",
                    ]:
                        import hashlib

                        with open(file_path, "rb") as f:
                            file_hash = hashlib.md5(f.read()).hexdigest()
                            logger.debug(
                                f"Saved {file_name} with MD5 hash: {file_hash}"
                            )

                except Exception as e:
                    logger.error(f"Error processing file {file_name}: {e}")
                    continue

                # Give execution permission to all files
                os.chmod(file_path, 0o755)

            # Add a command to copy testcase directory to /testcase in the container
            dockerfile_content += f"\nCOPY testcase /testcase\n"

            # Add apt-get install command if we have packages to install
            if packages_to_install:
                # Format the list of packages
                packages_str = " ".join(packages_to_install)
                # Add the RUN command to install packages
                dockerfile_content += f"\n# Install required packages\nRUN apt-get update && apt-get install -y {packages_str} && apt-get clean\n"
                logger.info(
                    f"Added apt-get install command for {len(packages_to_install)} packages in {instance_id}"
                )

            # Render Dockerfile template
            rendered_dockerfile = dockerfile_template.render(
                base_image=SECB_EVAL_BASE_IMAGE,
                dockerfile_content=dockerfile_content,
                script_name="secb",
                sanitizer=sanitizer,
                lang=lang,
                project_name=project_name,
                work_dir=work_dir,
                env_vars=env_vars,
            )

            dockerfile_path = os.path.join(temp_dir, "Dockerfile")
            with open(dockerfile_path, "w") as f:
                f.write(rendered_dockerfile)

            # Build the Docker image
            logger.info(f"Building Docker image for instance {instance_id}")
            build_cmd = ["docker", "build", "-t", image_name, temp_dir]

            docker_build_result = subprocess.run(
                build_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            build_status = {
                "instance_id": instance_id,
                "timestamp": time.time(),
                "docker_build_success": docker_build_result.returncode == 0,
            }

            if docker_build_result.returncode != 0:
                logger.error(
                    f"Failed to build image for {instance_id}: {docker_build_result.stderr}"
                )

                # Write build status to result file
                with open(result_file, "a") as f:
                    f.write(json.dumps(build_status) + "\n")

                return

            logger.info(f"Successfully built image {image_name}, validating...")

            # Validate the image by running tests
            validation_result = validate_image(
                client, image_name, work_dir, base_commit_hash, bool(repo_changes)
            )
            build_status.update(validation_result)

            # Write build status to result file
            with open(result_file, "a") as f:
                f.write(json.dumps(build_status) + "\n")

            # Keep or delete the image based on validation
            if validation_result["validation_success"]:
                logger.info(
                    f"Image validation successful for {instance_id}, generating tagged images."
                )

                # Create three different versions of the image with different tags
                # 1. latest - Keep all files
                latest_success, _ = cleanup_and_commit_image(
                    client, image_name, "latest"
                )
                if not latest_success:
                    logger.warning(f"Failed to create 'latest' tag for {image_name}")

                # 2. patch - Remove patch file (model_patch.diff)
                patch_success, patch_content = cleanup_and_commit_image(
                    client, image_name, "patch"
                )
                if not patch_success:
                    logger.warning(f"Failed to create 'patch' tag for {image_name}")

                # 3. poc - Remove both patch and poc files
                poc_success, _ = cleanup_and_commit_image(client, image_name, "poc")
                if not poc_success:
                    logger.warning(f"Failed to create 'poc' tag for {image_name}")

                # If validation was successful and we're creating a dataset, save this instance
                if dataset_output_file:
                    # Process the instance with validation results
                    dataset_instance = process_dataset_instance(
                        instance,
                        output_data,
                        cast(Dict[str, Any], validation_result),
                        patch_content,
                    )

                    # Write the instance to the dataset file
                    with open(dataset_output_file, "a") as f:
                        f.write(json.dumps(dataset_instance) + "\n")

                    logger.info(f"Saved verified dataset instance {instance_id}")
            else:
                logger.warning(
                    f"Image validation failed for {instance_id}, deleting the image {image_name}."
                )
                delete_cmd = ["docker", "rmi", "-f", image_name]
                subprocess.run(
                    delete_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )

    except Exception as e:
        logger.error(f"Error processing instance {instance_id}: {e}")
        traceback.print_exception(type(e), e, e.__traceback__)
        # Write error to result file
        logger.warning(f"Saving error to {result_file}")
        with open(result_file, "a") as f:
            error_status = {
                "instance_id": instance_id,
                "timestamp": time.time(),
                "error": str(e),
            }
            f.write(json.dumps(error_status) + "\n")


# Helper function for multiprocessing that can be properly pickled
def worker_wrapper(
    instance,
    latest_outputs,
    input_dir,
    result_file,
    dataset_output_file,
    force,
    template_dir,
):
    """
    Wrapper function for multiprocessing that creates a new Docker client
    for each worker process.
    """
    # Create a new Docker client inside the worker process
    client = docker.from_env()
    return process_instance_worker(
        instance=instance,
        latest_outputs=latest_outputs,
        input_dir=input_dir,
        result_file=result_file,
        dataset_output_file=dataset_output_file,
        client=client,
        force=force,
        template_dir=template_dir,
    )


def build_eval_instance(
    dataset_name: str,
    dataset_label: str,
    input_dir: str,
    output_file: str,
    dataset_output_file: str,
    force: bool = False,
    ids: Optional[List[str]] = None,
    num_workers: int = 1,
) -> None:
    """
    Build Docker images for each instance in the dataset.

    Args:
        dataset_name: The name of the HuggingFace dataset.
        dataset_label: The label of the dataset.
        input_dir: The path to the input directory with previous phase results.
        output_file: The path to save the result file.
        dataset_output_file: The path to save the dataset file in JSONL format.
        force: Whether to force rebuild images even if they already exist.
        ids: List of specific instance IDs to process. If None, process all instances.
        num_workers: Number of worker processes to use for parallel processing.
    """
    # Make sure the base image exists
    if not build_eval_base():
        logger.error("Could not build base image. Exiting.")
        return

    # Load the dataset
    logger.info(f"Loading dataset {dataset_name} with label {dataset_label}")
    dataset = datasets.load_dataset(dataset_name, split=dataset_label)

    # Get latest output.json files
    latest_outputs = explore_output_json(input_dir)

    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # Create dataset output directory if it doesn't exist
    if dataset_output_file:
        os.makedirs(os.path.dirname(dataset_output_file), exist_ok=True)
        # Initialize the dataset file with an empty file if it doesn't exist
        if not os.path.exists(dataset_output_file):
            with open(dataset_output_file, "w") as f:
                pass  # Create an empty file

    # Setup logging to file
    logger.add("output/build_eval_images.log", rotation="10 MB")

    # Result file for tracking build status
    result_file = output_file

    # Get the template directory path
    template_dir = os.path.join(os.path.dirname(__file__), "templates")

    # Filter instances by ID if specified
    if ids:
        dataset = [instance for instance in dataset if instance["instance_id"] in ids]
        logger.info(
            f"Filtered dataset to {len(dataset)} instances based on provided IDs"
        )

    # Determine number of workers to use
    if num_workers <= 0:
        # Auto-detect number of CPUs if num_workers <= 0
        num_workers = multiprocessing.cpu_count()
    num_workers = min(
        num_workers, len(dataset)
    )  # Don't use more workers than instances

    logger.info(f"Using {num_workers} worker processes for parallel processing")

    if num_workers == 1:
        # Single process mode
        logger.info("Running in single process mode")
        # Initialize Docker client
        try:
            client = docker.from_env()
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            return

        # Process each instance in the dataset sequentially
        for instance in dataset:
            process_instance_worker(
                instance,
                latest_outputs,
                input_dir,
                result_file,
                dataset_output_file,
                client,
                force,
                template_dir,
            )
    else:
        # Multiprocessing mode
        logger.info(f"Running in multiprocessing mode with {num_workers} workers")

        # Create a process pool
        with multiprocessing.Pool(processes=num_workers) as pool:
            # Create a partial function with fixed arguments
            worker_func = partial(
                worker_wrapper,
                latest_outputs=latest_outputs,
                input_dir=input_dir,
                result_file=result_file,
                dataset_output_file=dataset_output_file,
                force=force,
                template_dir=template_dir,
            )

            # Use the worker_func directly without lambda
            for _ in pool.imap_unordered(worker_func, dataset):
                pass

    # Log final dataset stats if dataset_output_file was specified
    if dataset_output_file:
        # Count the number of instances in the dataset file
        with open(dataset_output_file, "r") as f:
            processed_count = sum(1 for _ in f)
        logger.info(
            f"Dataset processing complete. Total instances saved: {processed_count}"
        )


def validate_image(
    client: docker.DockerClient,
    image_name: str,
    work_dir: str,
    base_commit_hash: str,
    repo_changes: bool,
) -> ValidationResultDict:
    """
    Validate a Docker image by running the build, exploit, and patch phases.

    Args:
        client: Docker client
        image_name: The name of the Docker image to validate.
        work_dir: The working directory in the container.
        base_commit_hash: The base commit hash to use for the build.
        repo_changes: Whether to apply repository changes before building.

    Returns:
        Dict: A dictionary with validation results.
    """
    result: ValidationResultDict = {
        "validation_success": False,
        "build_phase": {
            "success": False,
            "output": "",
            "error": "",
            "command": "",
            "skipped": False,
        },
        "exploit_phase": {
            "success": False,
            "output": "",
            "error": "",
            "command": "",
            "skipped": False,
        },
        "patch_phase": {
            "patch_success": False,
            "build_success": False,
            "repro_success": False,
            "output": "",
            "error": "",
            "patch_command": "",
            "build_command": "",
            "repro_command": "",
            "skipped": False,
        },
        "exit_code": None,  # Default value
    }

    try:
        # Create the list of commands to run in sequence
        commands = [
            f"cd {work_dir} && git reset --hard {base_commit_hash} && {BUILD_COMMAND}",  # Build phase
            REPRO_COMMAND,  # Exploit phase
            f"cd {work_dir} && git reset --hard {base_commit_hash} && {PATCH_COMMAND}",  # Patch phase 1/3: Apply patch
            f"{BUILD_COMMAND}",  # Patch phase 2/3: Build
            REPRO_COMMAND,  # Patch phase 3/3: Verify patch
        ]

        # Run all commands in the same container session with early termination on failure
        cmd_results = run_commands_in_session(
            client, image_name, commands, work_dir, stop_on_failure=True
        )
        executed_phases = len(cmd_results)

        # First capture all commands for reference
        build_cmd = commands[0]
        exploit_cmd = commands[1]
        patch_cmd = commands[2]
        patched_build_cmd = commands[3]
        patched_exploit_cmd = commands[4]

        result["build_phase"]["command"] = build_cmd
        result["exploit_phase"]["command"] = exploit_cmd
        result["patch_phase"]["patch_command"] = patch_cmd
        result["patch_phase"]["build_command"] = patched_build_cmd
        result["patch_phase"]["repro_command"] = patched_exploit_cmd

        # Build phase - must exist since at least one command is always run
        if executed_phases >= 1:
            # Build phase - success means build exited with code 0
            build_cmd, build_success, build_error, build_output = cmd_results[0]
            result["build_phase"]["success"] = build_success
            result["build_phase"]["output"] = build_output
            result["build_phase"]["error"] = build_error or ""
            result["build_phase"]["skipped"] = False

            if not build_success:
                logger.error(f"Build phase failed for {image_name}")
                # Mark other phases as skipped
                result["exploit_phase"]["skipped"] = True
                result["patch_phase"]["skipped"] = True
                return result

        # Exploit phase
        if executed_phases >= 2:
            # Exploit phase - success means we FOUND sanitizer errors
            exploit_cmd, exploit_success, exploit_error, exploit_output = cmd_results[1]
            result["exploit_phase"]["success"] = exploit_success  # Direct mapping
            result["exploit_phase"]["output"] = exploit_output
            result["exploit_phase"]["error"] = exploit_error or ""
            result["exploit_phase"]["skipped"] = False

            if not exploit_success:
                logger.error(
                    f"Exploit phase failed for {image_name} (no sanitizer errors detected)"
                )
                # Mark patch phase as skipped
                result["patch_phase"]["skipped"] = True
                return result
        else:
            result["exploit_phase"]["skipped"] = True

        # Patch application phase
        if executed_phases >= 3:
            # Patch application phase - success means patch command exited with code 0
            patch_cmd, patch_success, patch_error, patch_output = cmd_results[2]
            result["patch_phase"]["patch_success"] = patch_success
            result["patch_phase"]["output"] = f"Patch output: {patch_output}\n"
            result["patch_phase"]["error"] = f"Patch errors: {patch_error or ''}\n"
            result["patch_phase"]["skipped"] = False

            if not patch_success:
                logger.error(f"Patch application failed for {image_name}")
                return result
        else:
            result["patch_phase"]["skipped"] = True
            return result

        # Build after patch phase
        if executed_phases >= 4:
            # Build after patch phase - success means build command exited with code 0
            (
                patched_build_cmd,
                patched_build_success,
                patched_build_error,
                patched_build_output,
            ) = cmd_results[3]
            result["patch_phase"]["build_success"] = patched_build_success
            result["patch_phase"]["output"] += (
                f"Patched build output: {patched_build_output}\n"
            )
            result["patch_phase"]["error"] += (
                f"Patched build errors: {patched_build_error or ''}\n"
            )

            if not patched_build_success:
                logger.error(f"Build after patch failed for {image_name}")
                return result

        # Verify patch fixes vulnerability phase
        if executed_phases >= 5:
            # Verify patch fixes vulnerability phase
            # Due to is_patched logic in run_commands_in_session:
            # - After patch: success=True means NO sanitizer errors were found (good)
            (
                patched_exploit_cmd,
                patched_exploit_success,
                patched_exploit_error,
                patched_exploit_output,
            ) = cmd_results[4]

            # No need to invert the result anymore - success already means NO errors found
            result["patch_phase"]["repro_success"] = patched_exploit_success
            result["patch_phase"]["output"] += (
                f"Patched repro output: {patched_exploit_output}\n"
            )

            # Extract exit code from error message if available
            exit_code_match = re.search(r"Exit code: (\d+)", patched_exploit_error)
            if exit_code_match:
                result["exit_code"] = int(exit_code_match.group(1))
            else:
                # Default exit code based on success
                result["exit_code"] = 0 if patched_exploit_success else 1

            if not patched_exploit_success:
                logger.error(
                    f"Patch validation failed for {image_name} ({patched_exploit_error})"
                )
                return result

            # All validations passed
            result["validation_success"] = True
            logger.info(f"All validation phases passed for {image_name}")
        else:
            logger.error(
                f"Not all commands were executed for {image_name}. Got {executed_phases} results."
            )

    except Exception as e:
        logger.error(f"Error validating image {image_name}: {str(e)}")
        result["build_phase"]["error"] = str(e)
        result["exploit_phase"]["skipped"] = True
        result["patch_phase"]["skipped"] = True

    return result


def get_args():
    parser = argparse.ArgumentParser(description="Build Docker images for evaluation.")
    parser.add_argument(
        "--dataset",
        type=str,
        default="hwiwonl/SEC-bench_repro",
        help="The name of the HuggingFace dataset",
    )
    parser.add_argument(
        "--label", type=str, default="cve", help="The label of the HuggingFace dataset"
    )
    parser.add_argument(
        "--input-dir",
        type=str,
        required=True,
        help="The path to the input directory where result files exist",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        default="output/build_eval_images-target.jsonl",
        help="The path to save the result file",
    )
    parser.add_argument(
        "--dataset-output-file",
        type=str,
        help="The path to save the dataset file in JSONL format",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force rebuild images even if they already exist",
    )
    parser.add_argument(
        "--ids",
        type=str,
        nargs="+",
        help="List of instance IDs to process. If not provided, all instances will be processed.",
    )
    parser.add_argument(
        "--log-file",
        default="logs/build_eval_instances.log",
        help="Path to the log file.",
    )
    parser.add_argument(
        "--num-workers",
        type=int,
        default=1,
        help="Number of worker processes to use for parallel processing. Set to 0 to use all available CPU cores.",
    )

    args = parser.parse_args()
    return args


def main():
    # Parse command line arguments
    args = get_args()

    # Configure logging
    logger.remove()  # Remove default handler
    log_path = Path(args.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger.add(sys.stderr, level="INFO")  # Add console handler
    logger.add(args.log_file, level="DEBUG", rotation="10 MB")

    logger.info(
        f"Starting build process with dataset {args.dataset}, label {args.label}"
    )

    if args.ids:
        logger.info(f"Filtering to only process the following instance IDs: {args.ids}")
    if args.force:
        logger.info(
            "Force rebuild enabled: will rebuild images even if they already exist"
        )
    if args.dataset_output_file:
        logger.info(f"Save verified dataset to {args.dataset_output_file}")

    # Build evaluation images
    build_eval_instance(
        args.dataset,
        args.label,
        args.input_dir,
        args.output_file,
        args.dataset_output_file,
        force=args.force,
        ids=args.ids,
        num_workers=args.num_workers,
    )


if __name__ == "__main__":
    # Make sure file descriptors are properly closed in child processes to avoid leaks
    multiprocessing.set_start_method("spawn", force=True)
    main()
