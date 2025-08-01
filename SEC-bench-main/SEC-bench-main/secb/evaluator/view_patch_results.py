#!/usr/bin/env python3
"""SEC-bench Patch Results Viewer.

This module analyzes and displays patch evaluation results from different agents
(SWEA, OpenHands, Aider) in a structured format with statistics and cost analysis.

Features:
- Multi-agent result analysis (SWEA, OpenHands, Aider)
- Patch success rate calculation across evaluation types (strict, medium, generous)
- Failure type classification (No Patch, Incomplete Patch, Compilation Error, etc.)
- Cost analysis for each agent type
- Rich terminal output with tables and statistics
- Dataset filtering and indexing support

Usage:
    python view_patch_results.py --agent <agent> --input-dir <results_dir> [options]

Options:
    --agent {swea,oh,aider}  Agent type to analyze
    --input-dir PATH         Directory containing evaluation results
    --index N                Limit analysis to first N dataset instances

Output:
    Displays formatted tables showing:
    - Per-instance results across evaluation types
    - Summary statistics and success rates
    - Failure type breakdown
    - Cost analysis per agent
"""

import argparse
import json
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict
from enum import Enum

from rich import box
from rich.console import Console
from rich.table import Table
from loguru import logger
from datasets import load_dataset


class FailureType(Enum):
    NP = "No patch"  # The model failed to submit a patch
    IP = "Incomplete patch format"  # FAIL_STEP: Git apply;
    CE = "Compilation error"  # FAIL_STEP: Compile;
    FF = "Fail to fix"  # Run PoC timed out after, TENTATIVE: Run PoC;
    UNKNOWN = "Unknown failure"  # Default for unclassified failures


@dataclass
class PatchResult:
    instance_id: str
    success: bool
    reason: Optional[str] = None
    git_patch: Optional[str] = None
    eval_type: str = "unknown"  # Added eval_type field
    failure_type: Optional[FailureType] = None


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze patch results from input directory"
    )
    parser.add_argument(
        "--agent",
        required=True,
        choices=["swea", "oh", "aider"],
        help="Agent type (swea, oh, or aider)",
    )
    parser.add_argument(
        "--input-dir", required=True, help="Input directory containing report files"
    )
    parser.add_argument(
        "--index",
        type=int,
        help="Only consider instances up to this index in the dataset",
    )
    return parser.parse_args()


def format_boolean(value: bool) -> str:
    """Format boolean values as emoji."""
    return "✅" if value else "❌"


def determine_failure_type(reason: Optional[str]) -> Optional[FailureType]:
    """Determine the failure type based on the reason string."""
    if not reason:
        return None

    if "The model failed to submit a patch" in reason:
        return FailureType.NP
    elif "FAIL_STEP: Git apply;" in reason:
        return FailureType.IP
    elif "FAIL_STEP: Compile;" in reason:
        return FailureType.CE
    elif "Run PoC timed out after" in reason or "TENTATIVE: Run PoC;" in reason:
        return FailureType.FF
    else:
        return FailureType.UNKNOWN


def analyze_results(result_file: str, eval_type: str) -> List[PatchResult]:
    """Parse and analyze the results from a report file with specific evaluation type."""
    results = []

    try:
        with open(result_file, "r") as f:
            for line in f:
                if line.strip():  # Skip empty lines
                    data = json.loads(line)

                    # Extract reason and determine failure type
                    reason = data.get("reason")
                    failure_type = (
                        determine_failure_type(reason)
                        if not data.get("success", False)
                        else None
                    )

                    result = PatchResult(
                        instance_id=data.get("instance_id", "N/A"),
                        success=data.get("success", False),
                        reason=reason,
                        git_patch=data.get("git_patch"),
                        eval_type=eval_type,
                        failure_type=failure_type,
                    )
                    results.append(result)
    except Exception as e:
        print(f"Error loading result file {result_file}: {e}")

    return results


def calculate_statistics(results: List[PatchResult]) -> Dict[str, Any]:
    """Calculate statistics based on analysis results."""
    # Group results by evaluation type
    grouped_results: Dict[str, List[PatchResult]] = defaultdict(list)
    for result in results:
        grouped_results[result.eval_type].append(result)

    # Calculate stats for each group
    stats: Dict[str, Any] = {"by_type": {}}

    # Calculate stats for each evaluation type
    for eval_type, type_results in grouped_results.items():
        total = len(type_results)
        success_count = sum(1 for r in type_results if r.success)

        # Count failure types
        failure_counts: Dict[str, int] = defaultdict(int)
        for result in type_results:
            if not result.success and result.failure_type:
                failure_counts[result.failure_type.name] += 1

        type_stats: Dict[str, Any] = {
            "total": total,
            "success": success_count,
            "success_rate": "N/A",
            "failures": {
                "NP": failure_counts["NP"],
                "IP": failure_counts["IP"],
                "CE": failure_counts["CE"],
                "FF": failure_counts["FF"],
                "UNKNOWN": failure_counts["UNKNOWN"],
            },
        }

        if total > 0:
            type_stats["success_rate"] = (
                f"{success_count}/{total} ({success_count / total * 100:.1f}%)"
            )

        stats["by_type"][eval_type] = type_stats

    return stats


def create_table(results: List[PatchResult], agent_type: str) -> Table:
    """Create a rich table to display the results."""
    table = Table(title=f"Patch Results for {agent_type.upper()}", box=box.ROUNDED)

    # Add columns
    table.add_column("Instance ID", style="cyan")
    table.add_column("Strict", style="green")
    table.add_column("Medium", style="blue")
    table.add_column("Generous", style="magenta")
    table.add_column("Failure Type", style="yellow")
    table.add_column("Reason", style="yellow")

    # Group results by instance_id for easier lookup
    results_by_instance: Dict[str, Dict[str, PatchResult]] = {}
    for result in results:
        if result.instance_id not in results_by_instance:
            results_by_instance[result.instance_id] = {}
        results_by_instance[result.instance_id][result.eval_type] = result

    # Add rows for each unique instance_id
    for instance_id, type_results in results_by_instance.items():
        # Get success status for each evaluation type
        strict_result = type_results.get("strict")
        medium_result = type_results.get("medium")
        generous_result = type_results.get("generous")

        # Find any failure reason to display
        failure_reason = None
        failure_type = None

        # Prioritize showing failure from strict, then medium, then generous
        for eval_type in ["strict", "medium", "generous"]:
            if eval_type in type_results and not type_results[eval_type].success:
                result = type_results[eval_type]
                failure_reason = result.reason
                failure_type = (
                    result.failure_type.name if result.failure_type else "N/A"
                )
                break

        table.add_row(
            instance_id,
            format_boolean(strict_result.success) if strict_result else "—",
            format_boolean(medium_result.success) if medium_result else "—",
            format_boolean(generous_result.success) if generous_result else "—",
            failure_type or "",
            failure_reason or "",
        )

    return table


def create_stats_panel(stats: Dict[str, Any], agent_type: str) -> Table:
    """Create a table with statistics."""
    stats_table = Table(
        title=f"{agent_type.upper()} Results Summary",
        box=box.ROUNDED,
        border_style="blue",
    )

    # Add columns
    stats_table.add_column("Evaluation Type", style="cyan")
    stats_table.add_column("Total", style="yellow")
    stats_table.add_column("Success", style="green")
    stats_table.add_column("Success Rate", style="magenta")
    stats_table.add_column("NP", style="red")  # No Patch
    stats_table.add_column("IP", style="red")  # Incomplete Patch
    stats_table.add_column("CE", style="red")  # Compilation Error
    stats_table.add_column("FF", style="red")  # Fail to Fix
    stats_table.add_column("UNK", style="red")  # Unknown

    # Add rows for each type
    for eval_type, type_stats in stats["by_type"].items():
        stats_table.add_row(
            eval_type.capitalize(),
            str(type_stats["total"]),
            str(type_stats["success"]),
            type_stats["success_rate"],
            str(type_stats["failures"]["NP"]),
            str(type_stats["failures"]["IP"]),
            str(type_stats["failures"]["CE"]),
            str(type_stats["failures"]["FF"]),
            str(type_stats["failures"]["UNKNOWN"]),
        )

    return stats_table


def create_failure_description_panel() -> Table:
    """Create a panel explaining failure type abbreviations."""
    desc_table = Table(
        title="Failure Type Descriptions", box=box.ROUNDED, border_style="dim"
    )

    desc_table.add_column("Abbr", style="cyan", justify="right")
    desc_table.add_column("Description", style="yellow")

    desc_table.add_row("NP", "No patch submitted")
    desc_table.add_row("IP", "Incomplete patch format")
    desc_table.add_row("CE", "Compilation error")
    desc_table.add_row("FF", "Failed to fix vulnerability")
    desc_table.add_row("UNK", "Unknown failure reason")

    return desc_table


def calculate_cost_swea(
    input_dir: str, filtered_instances: Optional[Set[str]] = None
) -> Tuple[float, int]:
    """Calculate total cost for SWE-agent from trajectory files."""
    total_cost = 0
    total_file_cnt = 0
    target_files = [f for f in Path(input_dir).glob("**/*.traj")]
    logger.info(f"Found {len(target_files)} trajectory files in {input_dir}")

    for file in target_files:
        with open(file) as f:
            data = json.load(f)
            # If filtering is active, check if this instance should be included
            if filtered_instances is not None:
                instance_id = data.get("environment", "")
                if instance_id not in filtered_instances:
                    continue
            total_file_cnt += 1
            total_cost += data.get("info").get("model_stats").get("instance_cost", 0)

    return total_cost, total_file_cnt


def calculate_cost_oh(
    input_dir: str, filtered_instances: Optional[Set[str]] = None
) -> Tuple[float, int]:
    """Calculate total cost for OpenHands from json files."""
    total_cost = 0
    target_file = os.path.join(input_dir, "output.jsonl")
    total_instance_cnt = 0
    with open(target_file, "r") as f:
        for line in f:
            data = json.loads(line)
            # If filtering is active, check if this instance should be included
            if filtered_instances is not None:
                instance_id = data.get("instance_id")
                if instance_id not in filtered_instances:
                    continue
            total_instance_cnt += 1
            total_cost += data.get("metrics", {}).get("accumulated_cost", 0)

    return total_cost, total_instance_cnt


def calculate_cost_aider(
    input_dir: str, filtered_instances: Optional[Set[str]] = None
) -> Tuple[float, int, Dict[str, float]]:
    """Calculate total cost for Aider from json files, grouped by model."""

    def extract_aider_model_name(path: Path) -> Tuple[str, str]:
        """Extract model name and instance ID from directory pattern (aider--MODEL_NAME--INSTANCE_ID)."""
        dir_name = path.name if path.is_dir() else path.parent.name
        # Pattern to match: aider--MODEL_NAME--INSTANCE_ID
        # Example: aider--anthropic-claude-3-7-sonnet-20250219--faad2.cve-2018-20358
        parts = dir_name.split("--", 3)  # Split into max 3 parts
        if len(parts) >= 3:  # We have aider, model_name, and instance_id
            model_name = parts[1]
            instance_id = parts[2]
            return (model_name, instance_id)
        return (dir_name, "")

    total_cost = 0
    file_cnt = 0
    costs_by_model: Dict[str, float] = defaultdict(float)

    # Look for subdirectories starting with 'aider--'
    input_path = Path(input_dir)
    aider_dirs = [
        d for d in input_path.iterdir() if d.is_dir() and d.name.startswith("aider--")
    ]

    if not aider_dirs:
        logger.warning(f"No aider-- subdirectories found in {input_dir}")

    for aider_dir in aider_dirs:
        # Extract model name from directory name
        # logger.info(f"Processing aider directory: {aider_dir}")
        dir_model_name, instance_id = extract_aider_model_name(aider_dir)

        # If filtering is active and this instance isn't in the filtered set, skip it
        if filtered_instances is not None and instance_id is not None:
            if instance_id not in filtered_instances:
                continue

        # Process all JSON files in the directory
        for json_file in aider_dir.glob("*.json"):
            file_cnt += 1
            with open(json_file, "r") as f:
                data = json.load(f)

                # Convert to list for uniform processing
                items = data if isinstance(data, list) else [data]

                for item in items:
                    if not isinstance(item, dict):
                        continue

                    # Use model from JSON or fall back to directory name
                    model_name = item.get("model", dir_model_name)
                    item_cost = item.get("cost", 0)

                    # Add to total and model-specific costs
                    total_cost += item_cost
                    costs_by_model[model_name] += item_cost

    return total_cost, file_cnt, costs_by_model


def create_cost_panel(
    total_cost: float,
    file_count: int,
    agent_type: str,
    costs_by_model: Optional[Dict[str, float]] = None,
) -> Table:
    """Create a table showing cost information."""
    cost_table = Table(
        title=f"{agent_type.upper()} Cost Summary",
        box=box.ROUNDED,
        border_style="green",
    )

    cost_table.add_column("Metric", style="cyan")
    cost_table.add_column("Value", style="yellow")

    cost_table.add_row("Total Files", str(file_count))
    cost_table.add_row("Total Cost", f"${total_cost:.2f}")

    if file_count > 0:
        cost_table.add_row("Average Cost", f"${total_cost / file_count:.2f}")

    # Add per-model costs if available
    if costs_by_model:
        cost_table.add_row("", "")  # Empty row as separator
        cost_table.add_row("Cost by Model", "")

        for model_name, model_cost in costs_by_model.items():
            cost_table.add_row(f"  {model_name}", f"${model_cost:.2f}")

    return cost_table


def load_dataset_instances(index: Optional[int] = None) -> Set[str]:
    """Load instances from the SEC-bench dataset up to the specified index."""
    logger.info(f"Loading SEC-bench/SEC-bench dataset")
    dataset = load_dataset("SEC-bench/SEC-bench", split="eval")

    if index is None:
        # Return all instance IDs
        return {instance["instance_id"] for instance in dataset}

    # Return only instances up to the specified index
    return {dataset[i]["instance_id"] for i in range(min(index, len(dataset)))}


def main():
    args = parse_args()

    # Load dataset instances if index is specified
    filtered_instances = None
    if args.index is not None:
        filtered_instances = load_dataset_instances(args.index)
        logger.info(
            f"Filtering results to first {args.index} instances ({len(filtered_instances)} unique IDs)"
        )

    # Define report files to check
    report_files = {
        "strict": os.path.join(args.input_dir, "report_strict.jsonl"),
        "medium": os.path.join(args.input_dir, "report_medium.jsonl"),
        "generous": os.path.join(args.input_dir, "report_generous.jsonl"),
    }

    # Check if at least one report file exists
    found_files = [f for f in report_files.values() if os.path.exists(f)]
    if not found_files:
        logger.error(f"Error: No report files found in {args.input_dir}")
        logger.error(
            "Expected: report_strict.jsonl, report_medium.jsonl, report_generous.jsonl"
        )
        return

    # Analyze all results
    all_results = []
    for eval_type, file_path in report_files.items():
        if os.path.exists(file_path):
            type_results = analyze_results(file_path, eval_type)
            # Filter results if needed
            if filtered_instances is not None:
                type_results = [
                    r for r in type_results if r.instance_id in filtered_instances
                ]
            all_results.extend(type_results)
            logger.info(f"Found {len(type_results)} results in {eval_type} evaluation")
        else:
            logger.warning(f"Warning: {file_path} not found")

    if not all_results:
        logger.error("No results found in any of the report files")
        return

    # Calculate statistics
    stats = calculate_statistics(all_results)

    # Calculate cost based on agent type and filter if needed
    total_cost = 0
    file_count = 0
    costs_by_model = None

    if args.agent == "swea":
        total_cost, file_count = calculate_cost_swea(args.input_dir, filtered_instances)
    elif args.agent == "oh":
        total_cost, file_count = calculate_cost_oh(args.input_dir, filtered_instances)
    elif args.agent == "aider":
        total_cost, file_count, costs_by_model = calculate_cost_aider(
            args.input_dir, filtered_instances
        )

    # Create and display table and stats
    console = Console()
    console.print(create_table(all_results, args.agent))
    console.print("")  # Add space between table and stats
    console.print(create_stats_panel(stats, args.agent))
    console.print("")  # Add space
    console.print(create_failure_description_panel())

    # Display cost information if files were found
    if file_count > 0:
        console.print("")  # Add space
        console.print(
            create_cost_panel(total_cost, file_count, args.agent, costs_by_model)
        )
    else:
        logger.warning("No cost information available")


if __name__ == "__main__":
    main()
