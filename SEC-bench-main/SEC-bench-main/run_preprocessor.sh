#!/bin/bash

# Function to print usage
print_usage() {
    echo "Usage: $0 <mode> [options]"
    echo
    echo "Modes:"
    echo "  seed    - Parse CVE/OSV files and extract relevant information"
    echo "  report  - Extract bug descriptions from reference URLs"
    echo "  project - Generate project configurations for reproducing vulnerabilities"
    echo
    echo "Options for seed mode:"
    echo "  --input-dir <dir>           Directory containing input JSON files"
    echo "  --output-file <file>        Output file path (JSONL format)"
    echo "  --log-file <file>           Log file path (default: logs/seed.log)"
    echo "  --repo-lang-file <file>     Repository language mapping file"
    echo "  --verbose, -v               Enable verbose logging"
    echo
    echo "Options for report mode:"
    echo "  --input-file <file>         Input JSONL file containing preprocessed data"
    echo "  --output-file <file>        Output JSONL file path (with bug reports)"
    echo "  --reports-dir <dir>         Directory to store extracted bug reports"
    echo "  --log-file <file>           Log file path (default: logs/report.log)"
    echo "  --max-entries <n>           Maximum number of entries to process"
    echo "  --verbose, -v               Enable verbose logging"
    echo "  --type <type>               Select vulnerability type (CVE, OSV, or ALL)"
    echo "  --lang <lang>               Filter entries by programming language"
    echo "  --blacklist <repos>         Exclude entries from specified repositories"
    echo "  --whitelist <repos>         Include only entries from specified repositories"
    echo "  --oss-fuzz [config]         Filter entries by OSS-Fuzz projects"
    echo "  --fixed-only                Filter entries with non-empty fixed commit"
    echo
    echo "Options for project mode:"
    echo "  --input-file <file>         Input file path containing bug reports"
    echo "  --output-file <file>        Output file path containing project information"
    echo "  --max-entries <n>           Maximum number of entries to process"
    echo "  --log-file <file>           Log file path (default: logs/project.log)"
    echo "  --verbose, -v               Enable verbose logging"
    echo "  --tracking-file <file>      Path to the tracking file"
    echo "  --force, -f                 Force reprocessing of already processed entries"
    echo "  --append, -a                Append to the output file"
    echo "  --sanitizer-only            Only process entries that have a sanitizer error"
    echo "  --minimal                   Generate a minimalized Dockerfile and build script instead of using the original OSS-Fuzz files"
    echo "  -h, --help                  Show this help message and exit"
    echo
    echo "Examples:"
    echo "  $0 seed --input-dir ./data --output-file ./output/seed.jsonl"
    echo "  $0 report --input-file ./output/seed.jsonl --type CVE --oss-fuzz --lang C,C++,Java"
    echo "  $0 project --input-file ./output/report-cve-oss-c-cpp-java.jsonl --sanitizer-only"
}

# Function to generate structured output filename for report mode
generate_report_filename() {
    local input_file="$1"
    local type="${2:-all}"
    local oss_fuzz="${3:-no}"
    local lang="${4:-all}"
    local fixed_only="${5:-no}"
    local whitelist_projects="${6:-}"
    local blacklist_projects="${7:-}"
    
    # Convert type to lowercase
    type=$(echo "$type" | tr '[:upper:]' '[:lower:]')
    
    # Convert languages to lowercase and replace commas with hyphens
    lang=$(echo "$lang" | tr '[:upper:]' '[:lower:]' | tr ',' '-')
    
    # Build filename components
    local components=("report")
    [[ "$type" != "all" ]] && components+=("$type")
    [[ "$oss_fuzz" == "yes" ]] && components+=("oss")
    [[ "$lang" != "all" ]] && components+=("$lang")
    [[ "$fixed_only" == "yes" ]] && components+=("fixed")
    
    # Add whitelist projects with wl_ prefix if present
    if [[ -n "$whitelist_projects" ]]; then
        # Replace commas with underscores for whitelist projects
        local wl_projects=$(echo "$whitelist_projects" | tr ',' '_')
        components+=("wl_${wl_projects}")
    fi
    
    # Add blacklist projects with bl_ prefix if present
    if [[ -n "$blacklist_projects" ]]; then
        # Replace commas with underscores for blacklist projects
        local bl_projects=$(echo "$blacklist_projects" | tr ',' '_')
        components+=("bl_${bl_projects}")
    fi
    
    # Join components with hyphens
    local filename=$(IFS="-"; echo "${components[*]}")
    
    # Get directory from input file
    local dir=$(dirname "$input_file")
    
    # Return full path
    echo "$dir/${filename}.jsonl"
}

# Function to generate structured output filename for project mode
generate_project_filename() {
    local input_file="$1"
    local sanitizer_only="${2:-no}"
    local minimal="${3:-no}"
    # Get base name without extension
    local base=$(basename "$input_file" .jsonl)
    
    # Replace report- with project- in the base name
    base=${base/report-/project-}
    
    # Build filename components
    local components=("$base")
    [[ "$sanitizer_only" == "yes" ]] && components+=("sanitizer")
    [[ "$minimal" == "yes" ]] && components+=("minimal")
    
    # Join components with hyphens
    local filename=$(IFS="-"; echo "${components[*]}")
    
    # Get directory from input file
    local dir=$(dirname "$input_file")
    
    # Return full path
    echo "$dir/${filename}.jsonl"
}

# Function to parse report mode arguments
parse_report_args() {
    local type="all"
    local oss_fuzz="no"
    local lang="all"
    local fixed_only="no"
    local whitelist_projects=""
    local blacklist_projects=""
    local input_file=""
    local remaining_args=()
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            "--type")
                type="$2"
                remaining_args+=("$1" "$2")
                shift 2
                ;;
            "--oss-fuzz")
                oss_fuzz="yes"
                remaining_args+=("$1")
                shift
                ;;
            "--lang")
                lang="$2"
                remaining_args+=("$1" "$2")
                shift 2
                ;;
            "--fixed-only")
                fixed_only="yes"
                remaining_args+=("$1")
                shift
                ;;
            "--whitelist")
                whitelist_projects="$2"
                remaining_args+=("$1" "$2")
                shift 2
                ;;
            "--blacklist")
                blacklist_projects="$2"
                remaining_args+=("$1" "$2")
                shift 2
                ;;
            "--input-file")
                input_file="$2"
                remaining_args+=("$1" "$2")
                shift 2
                ;;
            *)
                remaining_args+=("$1")
                shift
                ;;
        esac
    done
    
    # Return values through global variables
    REPORT_TYPE="$type"
    REPORT_OSS_FUZZ="$oss_fuzz"
    REPORT_LANG="$lang"
    REPORT_FIXED_ONLY="$fixed_only"
    REPORT_WHITELIST="$whitelist_projects"
    REPORT_BLACKLIST="$blacklist_projects"
    REPORT_INPUT_FILE="$input_file"
    REPORT_REMAINING_ARGS=("${remaining_args[@]}")
}

# Function to parse project mode arguments
parse_project_args() {
    local sanitizer_only="no"
    local force="no"
    local append="no"
    local input_file=""
    local remaining_args=()
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            "--sanitizer-only")
                sanitizer_only="yes"
                remaining_args+=("$1")
                shift
                ;;
            "--force"|"-f")
                force="yes"
                remaining_args+=("$1")
                shift
                ;;
            "--append"|"-a")
                append="yes"
                remaining_args+=("$1")
                shift
                ;;
            "--input-file")
                input_file="$2"
                remaining_args+=("$1" "$2")
                shift 2
                ;;
            "--tracking-file")
                tracking_file="$2"
                remaining_args+=("$1" "$2")
                shift 2
                ;;
            "--minimal")
                minimal="yes"
                remaining_args+=("$1")
                shift
                ;;
            *)
                remaining_args+=("$1")
                shift
                ;;
        esac
    done
    
    # Return values through global variables
    PROJECT_SANITIZER_ONLY="$sanitizer_only"
    PROJECT_MINIMAL="$minimal"
    PROJECT_INPUT_FILE="$input_file"
    PROJECT_REMAINING_ARGS=("${remaining_args[@]}")
}

# Check if mode is provided
if [ $# -eq 0 ]; then
    print_usage
    exit 1
fi

# Get mode
MODE="$1"
shift

# Process arguments based on mode
case "$MODE" in
    "seed")
        # Parse seed mode arguments
        python -m secb.preprocessor.seed "$@"
        ;;
    "report")
        # Parse report mode arguments
        parse_report_args "$@"
        
        # Generate output filename
        output_file=$(generate_report_filename "$REPORT_INPUT_FILE" "$REPORT_TYPE" "$REPORT_OSS_FUZZ" "$REPORT_LANG" "$REPORT_FIXED_ONLY" "$REPORT_WHITELIST" "$REPORT_BLACKLIST")
        # echo -e "\033[32mOutput file: $output_file\033[0m"
        
        # Run report script with all arguments
        python -m secb.preprocessor.report "${REPORT_REMAINING_ARGS[@]}" --output-file "$output_file"
        ;;
    "project")
        # Parse project mode arguments
        parse_project_args "$@"
        
        # Generate output filename
        output_file=$(generate_project_filename "$PROJECT_INPUT_FILE" "$PROJECT_SANITIZER_ONLY" "$PROJECT_MINIMAL")
        # echo -e "\033[32mOutput file: $output_file\033[0m"
        
        # Run project script with all arguments
        python -m secb.preprocessor.project "${PROJECT_REMAINING_ARGS[@]}" --output-file "$output_file"
        ;;
    *)
        echo "Error: Unknown mode '$MODE'"
        print_usage
        exit 1
        ;;
esac