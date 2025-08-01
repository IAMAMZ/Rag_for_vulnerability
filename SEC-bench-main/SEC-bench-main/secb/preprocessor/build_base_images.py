#!/usr/bin/env python3
"""SEC-bench Base Image Builder.

This module builds foundational Docker images for all OSS-Fuzz base image versions
used in SEC-bench. Each base image includes OpenSSL, Python 3.11, and OpenHands
dependencies required for vulnerability evaluation.

Features:
- Build base images for all OSS-Fuzz base image versions
- Template-based Dockerfile generation using Jinja2
- Rich progress display with real-time build output
- Dry-run mode for testing configurations
- Force rebuild option for existing images
- Latest image building support
- Integration with OpenHands source code

Usage:
    python build_base_images.py --openhands-dir <path> [options]

Options:
    --openhands-dir PATH  Path to OpenHands source directory (required)
    --dry-run            Show build commands without executing
    --force              Force rebuild of existing images
    --latest             Build only the latest base image
    --help               Show usage information

Output:
    Docker base images with naming convention:
    hwiwonlee/secb.base:YYYYMMDD (e.g., hwiwonlee/secb.base:20241001)
"""

import select
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import jinja2
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.text import Text
from rich.traceback import install

from secb.preprocessor.constants import (
    OSS_FUZZ_BASE_IMAGE_VERSIONS,
    SECB_BASE_IMAGE_NAME,
)

# Install rich traceback handler
install()

# Create Rich console
console = Console()

# Setup Jinja2 environment
template_dir = Path(__file__).parent / "templates"
env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))
dockerfile_template = env.get_template("Dockerfile.base.j2")


def image_exists(image_tag):
    """Check if a Docker image with the given tag already exists."""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image_tag],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,  # Don't raise an exception if the command fails
        )
        # Return True if the command succeeded (return code 0)
        return result.returncode == 0
    except Exception:
        # If there was an error running the command, assume the image doesn't exist
        return False


def build_base_images(dry_run=False, force=False, latest=False, openhands_dir=None):
    """Build Docker images for all base versions with rich progress display."""
    if latest:
        # Only build one image if --latest is specified
        versions_to_build = [(None, "gcr.io/oss-fuzz-base/base-builder")]
        total_images = 1
    else:
        versions_to_build = OSS_FUZZ_BASE_IMAGE_VERSIONS
        total_images = len(versions_to_build)

    with console.status(
        f"Preparing to build {total_images} base images", spinner="dots"
    ) as _:
        time.sleep(1)  # Just for visual effect

    if not openhands_dir:
        console.print(
            "[bold red]Error: --openhands-dir is required when building base images[/bold red]"
        )
        raise ValueError("--openhands-dir is required when building base images")

    # Create progress display
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )

    # Create build output display
    build_output = Text()
    output_lines = []  # Keep track of lines separately

    # Create the main layout
    layout = Layout()
    layout.split_column(
        Layout(progress, name="progress", size=3),
        Layout(
            Panel(build_output, title="Docker Build Output", border_style="blue"),
            name="build_output",
            size=20,
        ),
    )

    # Create the main display
    main_layout = Layout()
    main_layout.split_column(
        Layout(
            Panel(layout, title="SEC-bench Base Image Builder", border_style="blue"),
            name="main_content",
            size=25,
        )
    )

    with Live(
        main_layout,
        refresh_per_second=4,
        console=console,
    ) as live:
        overall_task = progress.add_task(
            f"[green]Building {total_images} base images", total=total_images
        )

        for date, base_image in versions_to_build:
            # Format the tag based on latest flag
            if latest:
                image_tag = f"{SECB_BASE_IMAGE_NAME}:latest"
            else:
                # Format the date as YYYYMMDD for the tag
                tag_date = date.strftime("%Y%m%d")
                image_tag = f"{SECB_BASE_IMAGE_NAME}:{tag_date}"

            # Update the description for the main task
            progress.update(overall_task, description=f"[green]Processing {image_tag}")

            # Check if the image already exists
            if not force and image_exists(image_tag):
                console.print(
                    f"[bold yellow]⚠ Skipping existing image[/bold yellow] {image_tag}"
                )
                # Update overall progress and continue to the next image
                progress.update(overall_task, advance=1)
                continue

            # Create a temporary directory for the Dockerfile
            with tempfile.TemporaryDirectory(prefix="secb-base_") as temp_dir:
                # Copy the 'openhands' directory (Source code)
                shutil.copytree(
                    openhands_dir,
                    Path(temp_dir, "code", "openhands"),
                    ignore=shutil.ignore_patterns(
                        ".*/",
                        "__pycache__/",
                        "*.pyc",
                        "*.md",
                    ),
                )

                # Copy pyproject.toml and poetry.lock files
                for file in ["pyproject.toml", "poetry.lock"]:
                    src = Path(temp_dir, "code", "openhands", file)
                    if not src.exists():
                        src = openhands_dir.parent / file
                    shutil.copy2(src, Path(temp_dir, "code", file))

                # Create the Dockerfile with the template
                dockerfile_path = Path(temp_dir) / "Dockerfile"
                dockerfile_content = dockerfile_template.render(base_image=base_image)
                dockerfile_path.write_text(dockerfile_content)

                # Build the Docker image
                build_cmd = [
                    "docker",
                    "build",
                    "-t",
                    image_tag,
                    "-f",
                    str(dockerfile_path),
                    ".",
                ]

                if dry_run:
                    console.print(
                        Panel(
                            f"[bold yellow]Would run:[/bold yellow] {' '.join(build_cmd)}",
                            title="Dry Run",
                            border_style="yellow",
                        )
                    )
                    # Simulate progress in dry run mode
                    time.sleep(1)
                else:
                    current_image_task = progress.add_task(
                        f"[cyan]Building {image_tag} based on {base_image}",
                        total=None,  # Indeterminate progress
                    )

                    try:
                        # Run the build process
                        process = subprocess.Popen(
                            build_cmd,
                            cwd=temp_dir,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            bufsize=1,  # Line buffered
                        )

                        # Process output in real-time using select for non-blocking I/O
                        while True:
                            # Check if process has finished
                            if process.poll() is not None:
                                break

                            # Use select to check for available output without blocking
                            ready_to_read, _, _ = select.select(
                                [process.stdout, process.stderr],
                                [],
                                [],
                                0.1,  # 100ms timeout
                            )

                            # Process stdout
                            if process.stdout in ready_to_read:
                                stdout_line = process.stdout.readline()
                                if stdout_line:
                                    line = f"[green]{stdout_line.strip()}\n"
                                    output_lines.append(line)
                                    # Keep only the last 100 lines
                                    if len(output_lines) > 100:
                                        output_lines = output_lines[-100:]
                                    # Update the Text object with all lines
                                    build_output.plain = "".join(output_lines)

                            # Process stderr
                            if process.stderr in ready_to_read:
                                stderr_line = process.stderr.readline()
                                if stderr_line:
                                    line = f"[red]{stderr_line.strip()}\n"
                                    output_lines.append(line)
                                    # Keep only the last 100 lines
                                    if len(output_lines) > 100:
                                        output_lines = output_lines[-100:]
                                    # Update the Text object with all lines
                                    build_output.plain = "".join(output_lines)

                        # Get any remaining output
                        stdout_remainder, stderr_remainder = process.communicate()
                        if stdout_remainder:
                            line = f"[green]{stdout_remainder.strip()}\n"
                            output_lines.append(line)
                        if stderr_remainder:
                            line = f"[red]{stderr_remainder.strip()}\n"
                            output_lines.append(line)

                        # Update the Text object with all lines
                        build_output.plain = "".join(output_lines)

                        # Handle completion
                        if process.returncode == 0:
                            progress.remove_task(current_image_task)
                            console.print(
                                f"[bold green]✓ Successfully built[/bold green] {image_tag}"
                            )
                        else:
                            progress.remove_task(current_image_task)
                            console.print(
                                f"[bold red]✗ Error building[/bold red] {image_tag}"
                            )

                    except Exception as e:
                        progress.remove_task(current_image_task)
                        console.print(
                            f"[bold red]✗ Failed to execute build command for[/bold red] {image_tag}"
                        )
                        console.print(
                            Panel(str(e), title="Exception", border_style="red")
                        )

                # Update overall progress
                progress.update(overall_task, advance=1)

    console.print("[bold green]All base images have been processed![/bold green]")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Build base Docker images with Python 3.11 and OpenSSL"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print commands without executing them"
    )
    parser.add_argument(
        "--force", action="store_true", help="Rebuild images even if they already exist"
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Build a single 'latest' image using gcr.io/oss-fuzz-base/base-builder",
    )
    parser.add_argument(
        "--openhands-dir",
        type=Path,
        help="Path to the openhands source directory",
        default=Path(__file__).parent.parent / "AutoRE" / "openhands",
    )
    args = parser.parse_args()

    build_base_images(
        dry_run=args.dry_run,
        force=args.force,
        latest=args.latest,
        openhands_dir=args.openhands_dir,
    )
