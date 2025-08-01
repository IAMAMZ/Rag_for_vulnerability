"""Constants for SEC-bench preprocessor module.

This module contains all constants used throughout the SEC-bench preprocessor,
including Docker image versions, build patterns, and configuration settings.
"""

from datetime import datetime
from typing import List, Tuple, Dict

# Docker image configurations
SECB_BASE_IMAGE_NAME = "hwiwonlee/secb.base"

# OSS-Fuzz base image versions aligned with build dates
# Format: (datetime, image_version)
OSS_FUZZ_BASE_IMAGE_VERSIONS: List[Tuple[datetime, str]] = [
    # 2024
    (
        datetime(2024, 10, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:3ed2a94579619b4d7f04ba7ce6fd8b06c47e6fa7cfe13d9c1dd5a5f9ce52b311",
    ),
    (
        datetime(2024, 4, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:acf2772c5796db7799790825e04b0473b788a38c67aea29fd6fa1e875604e152",
    ),
    # 2023
    (
        datetime(2023, 10, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:3882b5f9465937a9bfbddd17f9cbc250a0bb599280c8ea339ba9570c89fcc858",
    ),
    (
        datetime(2023, 4, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:fa27e9c91e677be26faa71bb2586b53e4bc1f1ce26d76cb2887590721eb809ec",
    ),
    # 2022
    (
        datetime(2022, 10, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:59d74765190d3972ba80c960aa5bffd318536ce7a80b6dd873ab5a9dbbc76a5a",
    ),
    (
        datetime(2022, 4, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:dc05ffee2fc7ba046fcc474cf12c58aeb23130902c30484a1df7e8b0266c1bbb",
    ),
    # 2021
    (
        datetime(2021, 10, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:60876f1af9dbbad8b2104f9a71f526e28662630b4a7233213eeb60dfd366154b",
    ),
    (
        datetime(2021, 4, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:33e867708bc37c66adb1bc6e1551a1ed410d293c0c2b82d21473272f8f5217",
    ),
    # 2020
    (
        datetime(2020, 10, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:370a4534af2553fdc4f5b97700a01204221ceb0c10cec0b7ccfb6f3a262d1a63",
    ),
    (
        datetime(2020, 4, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:c0e58e3f95c0641bf018bc702ce93d1967e53af693c2f605505e2e45751ceebd",
    ),
    # 2019
    (
        datetime(2019, 10, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:1bcada7f67d4e1625922ff7754ba9c91e52f9e20241ef81b835a002e99b44731",
    ),
    (
        datetime(2019, 4, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:4a33c3b0e08ce91a21d3538bed789748e22066a755a5567228cb134bec257201",
    ),
    # 2018
    (
        datetime(2018, 10, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:3bfaa0922f3f4a690024b7424cd5ba4aa2e9b4b19d5ee8b3d1b5be41582e5e53",
    ),
    (
        datetime(2018, 4, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:4234a32d0f1adbbfb302d84171d19c0aca11fad3d5af442d877e1afca7b30f28",
    ),
    # 2017
    (
        datetime(2017, 10, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:c0a6a3f2c8f09ab5857698ca22533640e5c23cc9fdfed1283793738851e0cd01",
    ),
    (
        datetime(2017, 4, 1),
        "gcr.io/oss-fuzz-base/base-builder@sha256:c67a0ec9812c778e9298c110b61e35213167aecbffa376419693598768a52d59",
    ),
]

# Base image version mapping aligned with Ubuntu release cycles
# Format: (datetime, image_version)
BASE_IMAGE_VERSIONS: List[Tuple[datetime, str]] = [
    # 2024
    (
        datetime(2024, 10, 1),
        f"{SECB_BASE_IMAGE_NAME}:20241001",
    ),
    (
        datetime(2024, 4, 1),
        f"{SECB_BASE_IMAGE_NAME}:20240401",
    ),
    # 2023
    (
        datetime(2023, 10, 1),
        f"{SECB_BASE_IMAGE_NAME}:20231001",
    ),
    (
        datetime(2023, 4, 1),
        f"{SECB_BASE_IMAGE_NAME}:20230401",
    ),
    # 2022
    (
        datetime(2022, 10, 1),
        f"{SECB_BASE_IMAGE_NAME}:20221001",
    ),
    (
        datetime(2022, 4, 1),
        f"{SECB_BASE_IMAGE_NAME}:20220401",
    ),
    # 2021
    (
        datetime(2021, 10, 1),
        f"{SECB_BASE_IMAGE_NAME}:20211001",
    ),
    (
        datetime(2021, 4, 1),
        f"{SECB_BASE_IMAGE_NAME}:20210401",
    ),
    # 2020
    (
        datetime(2020, 10, 1),
        f"{SECB_BASE_IMAGE_NAME}:20201001",
    ),
    (
        datetime(2020, 4, 1),
        f"{SECB_BASE_IMAGE_NAME}:20200401",
    ),
    # 2019
    (
        datetime(2019, 10, 1),
        f"{SECB_BASE_IMAGE_NAME}:20191001",
    ),
    (
        datetime(2019, 4, 1),
        f"{SECB_BASE_IMAGE_NAME}:20190401",
    ),
    # 2018
    (
        datetime(2018, 10, 1),
        f"{SECB_BASE_IMAGE_NAME}:20181001",
    ),
    (
        datetime(2018, 4, 1),
        f"{SECB_BASE_IMAGE_NAME}:20180401",
    ),
    # 2017
    (
        datetime(2017, 10, 1),
        f"{SECB_BASE_IMAGE_NAME}:20171001",
    ),
    (
        datetime(2017, 4, 1),
        f"{SECB_BASE_IMAGE_NAME}:20170401",
    ),
]

# Build patterns for minimizing build scripts
# Core build commands and configuration patterns to keep
BUILD_PATTERNS: List[str] = [
    # Configuration and build tools
    r"\.\/configure",
    r"\.\/config\s",
    r"\.\/buildconf",
    r"\.\/autogen\.sh",
    r"\.\/bootstrap",
    r"cmake\s",
    r"meson\s",
    r"autoreconf\s",
    r"autoconf\s",
    r"automake\s",
    # Build commands
    r"^make(\s|$)",
    r"^ninja\s",
    r"^bazel\s",
    r"cargo\s",
    r"go\s+build",
    r"mvn\s",
    r"gradle\s",
    r"npm\s",
    r"pip\s",
    r"python\s+setup\.py",
    r"./setup\.sh",
    r"ant\s",
    # Project-specific build systems
    r"\.\/minirake",
    r"minirake\s",
    r"rake\s",
    r"gem\s+build",
    r"bundle\s",
    r"gem\s+install",
    # Common build helper scripts
    r"\.\/build\.sh",
    r"\.\/compile\.sh",
    r"\.\/build-dep",
    r"\.\/build_deps",
    # Common environment setup
    r"export\s+(CFLAGS|CXXFLAGS|LDFLAGS|CC|CXX|PATH|LD_LIBRARY_PATH|LD)",
    r"export\s+[A-Z_]+=",  # General export of environment variables
    # Directory navigation for build
    r"cd\s+\$SRC\/[^&;]*$",
    r"cd\s+build[^&;]*$",
    r"cd\s+\.\./build[^&;]*$",
    r"cd\s+\./build[^&;]*$",
    r"cd\s+build\/[^&;]*$",
    # Commented out because it matches too many commands
    # r"cd\s+[^&;]*$",
    r"mkdir\s+(-p\s+)?",
    # Package installation
    # This pattern matches 'apt install' commands but excludes cases where the
    # installation target is a local path (e.g., 'apt install ./package.deb')
    # The negative lookahead (?!\s+\./) ensures we only match system package installations
    r"apt-get\s+install(?!\s+\.\/)",
    r"apt\s+install(?!\s+\.\/)",
    r"yum\s+install",
    # Source code patching
    r"patch\s+",
    r"sed\s+-i\s+",
    # Configure flags and environment settings
    r"CONFIGURE_FLAGS",
    r"CMAKE_OPTIONS",
    r"MAKE_FLAGS",
    r"FLAGS=",
]

# Core build commands that should be prioritized
# These are essential for building the project regardless of fuzzing configuration
PRIORITY_BUILD_COMMANDS: List[str] = [
    r"\.\/configure",
    r"cmake\s",
    r"meson\s",
    r"\.\/buildconf",
    r"\.\/autogen\.sh",
    r"^make(\s|$)",
    r"^ninja\s",
    r"\.\/minirake",
    r"cargo\s+build",
    r"go\s+build",
]

# Patterns to exclude (fuzzer-specific) when minimizing build scripts
EXCLUDE_PATTERNS: List[str] = [
    # OSS-Fuzz specific output directories and commands
    r"\$OUT\/",
    r"LIB_FUZZING_ENGINE",
    r"libFuzzer",
    # Don't match just "fuzzer" as it might be part of configure flags
    r"fuzzer\.c",
    r"fuzz\-",
    r"fuzz_",
    # r"\-fuzz",        # This is colliding with `--enable-fuzzer` option
    r"AddressSanitizer",
    r"UndefinedBehaviorSanitizer",
    r"MemorySanitizer",
    # Corpus and dictionary handling
    r"corpus",
    r"dict",
    r"seed_corpus",
    # r"\.zip",
    # Generate/copy fuzzer targets
    r"cp\s+.*fuzz",
    r"for\s+f\s+in.*fuzz",
    r"afl",
    r"oss-fuzz",
    # OSS-Fuzz environment variables and constants
    r"FUZZING_BUILD_MODE",
    r"FUZZ_",
    r"--coverage",
    # Output directories for fuzzers
    r"genfiles",
    # Custom debian package installation
    r"apt install ./",
    r"apt-get install ./",
    # Custom directory creation
    r"mkdir \$format",  # Imagemagick
]

# Fuzzer loop patterns for identifying fuzzer-specific build loops
FUZZER_LOOP_PATTERNS: List[str] = [
    r"for\s+\w+\s+in\s+.*\*_fuzzer\b",
    r"for\s+\w+\s+in\s+.*fuzz\w*\.c",
    r"for\s+\w+\s+in\s+\$(\w+\/)*fuzz",
    r"for\s+\w+\s+in\s+.*\.zip",
    r"for\s+\w+\s+in\s+\$SRC\/\w+_fuzzer",
    r"for\s+\w+\s+in\s+\$SRC\/.*corpus",
]

# Command-specific exclusion options mapping
# Dictionary mapping command patterns to options that should be excluded
COMMAND_EXCLUSION_OPTIONS: Dict[str, List[str]] = {
    r"\.\/configure": [
        "--enable-fuzzer",
        "$BUILD_FLAG",
        # "--enable-option-checking=fatal",
        # "--enable-debug",
        # "--enable-coverage",
    ],
    r"\.\/cmake": [
        "-DENABLE_FUZZER=ON",
        "-DENABLE_COVERAGE=ON",
    ],
    r"\.\/meson": [
        "-Dfuzzer=true",
        "-Dfuzzing_engine=libfuzzer",
    ],
}

# OSV repository mapping for handling repository URL transformations
# Maps project names to (original_url, github_mirror_url) tuples
OSV_MAPPING: Dict[str, Tuple[str, str]] = {
    "dnsmasq": (
        "git://thekelleys.org.uk/dnsmasq.git",
        "https://github.com/infrastructureservices/dnsmasq",
    ),
    "ffmpeg": ("https://git.ffmpeg.org/ffmpeg.git", "https://github.com/ffmpeg/ffmpeg"),
    "jbig2dec": (
        "git://git.ghostscript.com/jbig2dec.git",
        "https://github.com/artifexsoftware/jbig2dec",
    ),
    "libpng-proto": (
        "https://git.code.sf.net/p/libpng/code libpng-code",
        "https://github.com/glennrp/libpng.git",
    ),
    "libreoffice": (
        "https://git.libreoffice.org/core",
        "https://github.com/libreoffice/core",
    ),
    "libssh": (
        "https://git.libssh.org/projects/libssh.git",
        "https://gitlab.com/libssh/libssh-mirror",
    ),
    "libtheora": ("https://git.xiph.org/theora.git", "https://github.com/xiph/theora"),
    "libvpx": (
        "https://chromium.googlesource.com/webm/libvpx",
        "https://github.com/webmproject/libvpx",
    ),
    "libwebp": (
        "https://chromium.googlesource.com/webm/libwebp",
        "https://github.com/webmproject/libwebp",
    ),
    "mupdf": (
        "git://git.ghostscript.com/mupdf.git",
        "https://github.com/artifexsoftware/mupdf",
    ),
    "net-snmp": (
        "git://git.code.sf.net/p/net-snmp/code",
        "https://github.com/net-snmp/net-snmp",
    ),
    "perfetto": (
        "https://android.googlesource.com/platform/external/perfetto/",
        "https://github.com/google/perfetto",
    ),
    "qemu": ("https://git.qemu.org/git/qemu.git", "https://github.com/qemu/qemu"),
    "libfdk-aac": (
        "https://android.googlesource.com/platform/external/aac/",
        "https://github.com/nu774/fdkaac",
    ),
    "xerces-c": (
        "https://svn.apache.org/repos/asf/xerces/c/trunk",
        "https://github.com/apache/xerces-c",
    ),
    "samba": ("https://git.samba.org/samba.git", "https://github.com/samba-team/samba"),
}
