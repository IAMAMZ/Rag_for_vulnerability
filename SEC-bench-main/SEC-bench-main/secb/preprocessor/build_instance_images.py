#!/usr/bin/env python3
"""SEC-bench Instance Image Builder.

This module builds vulnerability-specific Docker images from processed project
configurations. Each instance image contains a configured vulnerable environment
ready for reproduction and patching evaluation.

Features:
- Build Docker images for specific vulnerability instances
- Multi-threaded parallel processing for efficiency
- Template-based Dockerfile and helper script generation
- Configurable instance filtering (by ID or pattern)
- Rich progress tracking and logging
- Helper script integration for standardized commands
- Support for additional files and custom build scripts

Usage:
    python build_instance_images.py --input-file <project_file> [options]

Options:
    --input-file PATH     Input file containing project configurations (JSONL)
    --ids IDS             Comma-separated list of instance IDs to build
    --filter PATTERN      Build instances matching the pattern
    --num-workers N       Number of parallel build workers (default: CPU count)
    --help               Show usage information

Output:
    Docker instance images with naming convention:
    hwiwonlee/secb.x86_64.[instance_id]:latest
"""

import argparse
import json
import re
import subprocess
import tempfile
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

import jinja2
from loguru import logger
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

# Initialize console for rich output
console = Console()
# Lock for synchronizing console output between processes
console_lock = Lock()


def get_project_name_for_oss_fuzz(project_name: str) -> str:
    """Get the project name for OSS-Fuzz."""
    # Split by '/' and take the last part
    name = project_name.split("/")[-1]

    # Replace underscores with hyphens
    name = name.replace("_", "-")

    # Special case conversions
    if name == "php-src":
        name = "php"

    return name


def build_instance_image(instance: dict, process_idx: int = 0) -> tuple:
    """Builds a Docker image for a single instance.

    Args:
        instance: Dictionary containing instance data
        process_idx: Process index for logging purposes

    Returns:
        Tuple of (instance_id, success_flag)
    """
    instance_id = instance.get("instance_id", "unknown_instance")
    repo = instance.get("repo")
    lang = instance.get("lang", "c++")
    work_dir = instance.get("work_dir")
    sanitizer = instance.get("sanitizer", "address")
    dockerfile_content = instance.get("dockerfile")
    build_sh_content = instance.get("build_sh")
    additional_files = instance.get("additional_files", [])

    if not all([instance_id, repo, lang, dockerfile_content, build_sh_content]):
        with console_lock:
            logger.error(f"Missing required fields for instance: {instance_id}")
        return instance_id, False

    # Ensure required fields exist
    assert repo is not None and build_sh_content is not None and work_dir is not None

    try:
        project_name = get_project_name_for_oss_fuzz(repo)
        target_image_tag = f"hwiwonlee/secb.x86_64.{instance_id}:latest"
        with console_lock:
            logger.info(f"[Worker {process_idx}] Target image tag: {target_image_tag}")

        script_name = "secb"  # Name of the helper script

        # Prepare build environment without using progress display (to avoid nesting issues)
        with console_lock:
            console.print(
                f"[bold blue][Worker {process_idx}] Preparing build environment for {instance_id}...[/bold blue]"
            )

        # Load Jinja2 template
        template_path = Path(__file__).parent / "templates/secb_helper.sh.j2"
        if not template_path.is_file():
            with console_lock:
                logger.error(f"Template file not found: {template_path}")
            return instance_id, False
        template = jinja2.Template(template_path.read_text())

        # Render the template
        helper_script_content = template.render(
            instance_id=instance_id, script_name=script_name, work_dir=work_dir
        )

        with tempfile.TemporaryDirectory(
            prefix=f"secb-build-{instance_id}_"
        ) as build_dir_str:
            build_dir = Path(build_dir_str)

            # Create helper script (secb)
            helper_script_path = build_dir / script_name
            helper_script_path.write_text(helper_script_content)
            helper_script_path.chmod(0o755)  # Make executable
            with console_lock:
                console.print(
                    f"[dim][Worker {process_idx}] Generated helper script: {helper_script_path}[/dim]"
                )
                logger.info(
                    f"[Worker {process_idx}] Generated helper script: {helper_script_path}"
                )

            # Load and render Dockerfile template
            dockerfile_template_path = (
                Path(__file__).parent / "templates/Dockerfile.instance.j2"
            )
            if not dockerfile_template_path.is_file():
                with console_lock:
                    logger.error(
                        f"Dockerfile template not found: {dockerfile_template_path}"
                    )
                return instance_id, False
            dockerfile_template = jinja2.Template(dockerfile_template_path.read_text())
            final_dockerfile_content = dockerfile_template.render(
                dockerfile_content=dockerfile_content,
                script_name=script_name,
                sanitizer=sanitizer,
                lang=lang,
                project_name=project_name,
                work_dir=work_dir,
            )

            # Write final Dockerfile
            dockerfile_path = build_dir / "Dockerfile"
            dockerfile_path.write_text(final_dockerfile_content)
            with console_lock:
                console.print(
                    f"[dim][Worker {process_idx}] Generated Dockerfile: {dockerfile_path}[/dim]"
                )
                logger.info(
                    f"[Worker {process_idx}] Generated Dockerfile: {dockerfile_path}"
                )

            # Write build.sh
            build_sh_path = build_dir / "build.sh"
            build_sh_path.write_text(build_sh_content)
            with console_lock:
                console.print(
                    f"[dim][Worker {process_idx}] Wrote build script: {build_sh_path}[/dim]"
                )
                logger.info(
                    f"[Worker {process_idx}] Wrote build script: {build_sh_path}"
                )

            # Write additional files
            for file_info in additional_files:
                filename = file_info.get("filename")
                content = file_info.get("content")
                if filename and content is not None:
                    # Ensure target directory exists if filename includes path separators
                    target_path = build_dir / filename
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    target_path.write_text(content)
                    with console_lock:
                        console.print(
                            f"[dim][Worker {process_idx}] Wrote additional file: {target_path}[/dim]"
                        )
                        logger.info(
                            f"[Worker {process_idx}] Wrote additional file: {target_path}"
                        )
                else:
                    with console_lock:
                        logger.warning(
                            f"[Worker {process_idx}] Skipping invalid additional file entry for {instance_id}: {file_info}"
                        )

            # Build the Docker image
            with console_lock:
                console.print(
                    f"[bold cyan][Worker {process_idx}] Starting Docker build for {target_image_tag}[/bold cyan]"
                )
                logger.info(
                    f"[Worker {process_idx}] Starting Docker build for {target_image_tag} in {build_dir}"
                )

            build_cmd = [
                "docker",
                "build",
                "--progress=plain",  # Show detailed output
                "-t",
                target_image_tag,
                "-f",
                str(dockerfile_path),
                str(build_dir),  # Context directory
            ]
            with console_lock:
                logger.debug(
                    f"[Worker {process_idx}] Executing command: {' '.join(build_cmd)}"
                )

            process = subprocess.Popen(
                build_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Redirect stderr to stdout
                text=True,
                bufsize=1,  # Line buffered
            )

            # Stream output with simpler formatting (no nested progress)
            current_step = ""
            line_count = 0
            if process.stdout:
                for line in iter(process.stdout.readline, ""):
                    line = line.strip()
                    line_count += 1

                    # Detect build steps for better visibility
                    with console_lock:
                        if line.startswith("Step "):
                            current_step = line
                            console.print(f"[blue][Worker {process_idx}] {line}[/blue]")
                        elif "-->" in line:
                            # Show the result of a step
                            console.print(f"[dim][Worker {process_idx}] {line}[/dim]")
                        elif "error:" in line.lower() or "failed" in line.lower():
                            console.print(f"[red][Worker {process_idx}] {line}[/red]")
                        else:
                            # Don't print every line to console to avoid flooding
                            # Only show critical info or every 10th line
                            if line_count % 10 == 0 or any(
                                kw in line.lower()
                                for kw in ["warning", "error", "success"]
                            ):
                                console.print(
                                    f"[dim][Worker {process_idx}] {line}[/dim]"
                                )

                        # Always log to file
                        logger.info(
                            f"[BUILD {instance_id}][Worker {process_idx}] {line}"
                        )

                process.stdout.close()

            return_code = process.wait()

            if return_code == 0:
                with console_lock:
                    console.print(
                        f"[bold green][Worker {process_idx}] Successfully built image: {target_image_tag}[/bold green]"
                    )
                    logger.info(
                        f"[Worker {process_idx}] Successfully built image: {target_image_tag}"
                    )
                return instance_id, True
            else:
                with console_lock:
                    console.print(
                        f"[bold red][Worker {process_idx}] Docker build failed for {target_image_tag} with return code {return_code}.[/bold red]"
                    )
                    logger.error(
                        f"[Worker {process_idx}] Docker build failed for {target_image_tag} with return code {return_code}."
                    )
                return instance_id, False

    except Exception as e:
        with console_lock:
            console.print(
                f"[bold red][Worker {process_idx}] Error building {instance_id}: {str(e)}[/bold red]"
            )
            logger.exception(
                f"[Worker {process_idx}] An unexpected error occurred while building image for {instance_id}: {e}"
            )
        return instance_id, False


# Move the worker function outside of main() to make it picklable
def process_instance_with_index(idx, instance):
    """Process an instance with a given worker index.

    Args:
        idx: Worker index (0-based)
        instance: Instance data dictionary

    Returns:
        Tuple of (instance_id, success_flag)
    """
    process_idx = idx + 1  # 1-based index for display
    instance_id, success = build_instance_image(instance, process_idx)
    return instance_id, success


def get_args():
    parser = argparse.ArgumentParser(
        description="Build instance-specific Docker images for SEC-bench."
    )
    parser.add_argument(
        "--input-file",
        required=True,
        type=Path,
        help="Path to the input JSONL file containing instance data.",
    )
    parser.add_argument(
        "--ids",
        nargs="+",
        help="Optional list of specific instance IDs to build. If not provided, builds all.",
    )
    parser.add_argument(
        "--filter",
        type=str,
        help="Regex pattern to filter instance IDs. Only instances with matching IDs will be built.",
    )
    parser.add_argument(
        "--log-file",
        default="logs/build_instance_images.log",
        help="Path to the log file.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes to use for parallel image building (default: 1)",
    )

    args = parser.parse_args()
    return args


def main():
    args = get_args()

    # Configure logger
    logger.remove()  # Remove default handler
    log_path = Path(args.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger.add(args.log_file, level="INFO" if not args.verbose else "DEBUG")
    logger.add(lambda msg: console.print(f"[dim]{msg}[/dim]") if args.verbose else None)

    if not args.input_file.is_file():
        logger.error(f"Input file not found: {args.input_file}")
        return

    # Load instances
    instances_to_build = []
    try:
        with open(args.input_file, "r") as f:
            for line in f:
                try:
                    instance = json.loads(line.strip())
                    instance_id = instance.get("instance_id")
                    if not instance_id:
                        logger.warning("Skipping instance with missing 'instance_id'")
                        continue

                    # Filter by IDs if provided
                    if args.ids is not None and instance_id not in args.ids:
                        logger.debug(
                            f"Skipping instance {instance_id} as it's not in the requested IDs."
                        )
                        continue

                    # Filter by regex pattern if provided
                    if args.filter is not None and not re.search(
                        args.filter, instance_id
                    ):
                        logger.debug(
                            f"Skipping instance {instance_id} as it doesn't match the regex pattern: {args.filter}"
                        )
                        continue

                    instances_to_build.append(instance)

                except json.JSONDecodeError:
                    logger.warning(
                        f"Skipping invalid JSON line in {args.input_file}: {line.strip()}"
                    )
    except IOError as e:
        logger.error(f"Error reading input file {args.input_file}: {e}")
        return

    if not instances_to_build:
        logger.info("No instances selected or found to build.")
        return

    total_instances = len(instances_to_build)
    workers = min(args.workers, total_instances)

    logger.info(
        f"Attempting to build {total_instances} instance images with {workers} worker processes..."
    )

    success_count = 0
    failure_count = 0
    results = {}  # To track results by instance_id

    # Use single process if workers=1
    if workers == 1:
        logger.info("Running in single-process mode")

        # Create a single progress display for the entire process
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            overall_task = progress.add_task(
                f"[green]Building {total_instances} instances", total=total_instances
            )

            for i, instance in enumerate(instances_to_build):
                instance_id = instance.get("instance_id", "unknown")

                # Update progress display to show current instance
                progress.update(
                    overall_task,
                    description=f"[green]Building instances ({i + 1}/{total_instances}): {instance_id}",
                )

                # Log the instance we're working on
                logger.info(f"--- Processing instance: {instance_id} ---")

                # Temporarily pause progress display while building
                progress.stop()

                # Build the instance
                instance_id, success = build_instance_image(instance)
                results[instance_id] = success

                # Resume progress display
                progress.start()

                # Update progress based on result
                if success:
                    success_count += 1
                    console.print(f"[green]✓ {instance_id} - Success[/green]")
                else:
                    failure_count += 1
                    console.print(f"[red]✗ {instance_id} - Failed[/red]")

                # Advance the overall progress
                progress.update(overall_task, advance=1)
                logger.info(f"--- Finished instance: {instance_id} ---")
    else:
        logger.info(f"Running with {workers} parallel workers")

        # Track completed instances
        completed = 0

        # Create a progress bar for overall tracking
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            overall_task = progress.add_task(
                f"[green]Building {total_instances} instances with {workers} workers",
                total=total_instances,
            )

            # Use ProcessPoolExecutor for parallel processing
            with ProcessPoolExecutor(max_workers=workers) as executor:
                # Submit all jobs
                future_to_instance = {
                    executor.submit(process_instance_with_index, i, instance): instance
                    for i, instance in enumerate(instances_to_build)
                }

                # Process results as they complete
                for future in as_completed(future_to_instance):
                    instance = future_to_instance[future]
                    instance_id = instance.get("instance_id", "unknown")

                    try:
                        result_id, success = future.result()
                        results[result_id] = success

                        # Update counts
                        if success:
                            success_count += 1
                            with console_lock:
                                console.print(f"[green]✓ {result_id} - Success[/green]")
                        else:
                            failure_count += 1
                            with console_lock:
                                console.print(f"[red]✗ {result_id} - Failed[/red]")

                        # Update progress
                        completed += 1
                        progress.update(
                            overall_task,
                            advance=1,
                            description=f"[green]Completed {completed}/{total_instances} instances",
                        )

                    except Exception as exc:
                        with console_lock:
                            logger.error(f"{instance_id} generated an exception: {exc}")
                            console.print(
                                f"[red]✗ {instance_id} - Exception: {exc}[/red]"
                            )
                        failure_count += 1
                        completed += 1
                        progress.update(overall_task, advance=1)

    # Display final summary
    console.print("\n[bold]--- Build Summary ---[/bold]")
    console.print(f"Total instances processed: {total_instances}")
    console.print(f"[green]Successful builds: {success_count}[/green]")
    console.print(f"[red]Failed builds: {failure_count}[/red]")

    # Log summary to file as well
    logger.info("--- Build Summary ---")
    logger.info(f"Total instances processed: {total_instances}")
    logger.info(f"Successful builds: {success_count}")
    logger.info(f"Failed builds: {failure_count}")


if __name__ == "__main__":
    multiprocessing.set_start_method("spawn", force=True)
    main()
