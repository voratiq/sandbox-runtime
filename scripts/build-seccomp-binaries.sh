#!/bin/bash
set -euo pipefail

# Build static seccomp binaries for Linux using Docker
# This creates self-contained binaries that don't require gcc/clang/libseccomp-dev at runtime
#
# Usage: ./scripts/build-seccomp-binaries.sh
#
# Output: Creates BPF filters in vendor/seccomp/{x64,arm64}/
#
# Note: BPF bytecode is architecture-specific but libc-independent,
# so we only need one BPF file per architecture (not separate glibc/musl versions)

echo "Building static seccomp binaries using Docker..."

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is required but not installed"
    exit 1
fi

# Source directory with C files
SOURCE_DIR="$ROOT_DIR/vendor/seccomp-src"

if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: Source directory not found: $SOURCE_DIR"
    echo "Make sure vendor/seccomp-src/ exists with the C source files"
    exit 1
fi

# Define platforms to build
# Format: docker_platform:vendor_dir:base_image:image_version
# Note: We use Ubuntu (glibc) for building, but the resulting BPF bytecode
# is libc-independent and works with both glibc and musl
PLATFORMS=(
    "linux/amd64:x64:ubuntu:22.04"
    "linux/arm64:arm64:ubuntu:22.04"
)

# Function to build for a specific platform
build_platform() {
    local docker_platform="$1"
    local vendor_dir="$2"
    local base_image="$3"
    local image_version="$4"

    local output_dir="$ROOT_DIR/vendor/seccomp/$vendor_dir"
    local bpf_file="$output_dir/unix-block.bpf"
    local apply_seccomp_bin="$output_dir/apply-seccomp"

    echo ""
    echo "=========================================="
    echo "Building for: $vendor_dir ($docker_platform)"
    echo "=========================================="

    # Check if both BPF file and apply-seccomp binary already exist
    if [ -f "$bpf_file" ] && [ -f "$apply_seccomp_bin" ]; then
        echo "⊙ Files already exist, skipping build:"
        echo "  - BPF filter: $bpf_file ($(ls -lh "$bpf_file" | awk '{print $5}'))"
        echo "  - apply-seccomp: $apply_seccomp_bin ($(ls -lh "$apply_seccomp_bin" | awk '{print $5}'))"
        return 0
    fi

    # Create output directory
    mkdir -p "$output_dir"

    # Build using Ubuntu (glibc)
    # Note: The resulting BPF bytecode is libc-independent
    docker run --rm --platform "$docker_platform" \
        -v "$SOURCE_DIR:/src:ro" \
        -v "$output_dir:/output" \
        "$base_image:$image_version" sh -c "
            set -e
            echo 'Installing build dependencies...'
            apt-get update -qq
            apt-get install -y -qq gcc libseccomp-dev file > /dev/null

            echo 'Building seccomp-unix-block (requires libseccomp)...'
            gcc -o /output/seccomp-unix-block /src/seccomp-unix-block.c \
                -static -lseccomp \
                -O2 -Wall -Wextra

            echo 'Stripping debug symbols...'
            strip /output/seccomp-unix-block

            echo 'Setting permissions...'
            chmod +x /output/seccomp-unix-block

            echo 'Verifying binary...'
            file /output/seccomp-unix-block

            echo 'Testing static linkage...'
            ldd /output/seccomp-unix-block 2>&1 || echo '(static binary - no dynamic dependencies)'

            echo 'Binary size:'
            ls -lh /output/seccomp-unix-block

            echo ''
            echo 'Building apply-seccomp (no libseccomp dependency)...'
            gcc -o /output/apply-seccomp /src/apply-seccomp.c \
                -static \
                -O2 -Wall -Wextra

            echo 'Stripping apply-seccomp...'
            strip /output/apply-seccomp

            echo 'Setting permissions...'
            chmod +x /output/apply-seccomp

            echo 'Verifying apply-seccomp binary...'
            file /output/apply-seccomp

            echo 'Testing static linkage...'
            ldd /output/apply-seccomp 2>&1 || echo '(static binary - no dynamic dependencies)'

            echo 'Binary size:'
            ls -lh /output/apply-seccomp
        " || {
            echo "Error: Build failed for $vendor_dir"
            return 1
        }

    # Verify binary exists
    if [ ! -f "$output_dir/seccomp-unix-block" ]; then
        echo "✗ Error: Binary not found in $output_dir"
        return 1
    fi

    # Generate BPF filter using the seccomp-unix-block binary
    echo "Generating BPF filter..."
    local bpf_file="$output_dir/unix-block.bpf"

    # Run the generator to create the BPF file
    if ! "$output_dir/seccomp-unix-block" "$bpf_file" 2>&1; then
        echo "✗ Error: Failed to generate BPF filter"
        return 1
    fi

    # Verify BPF file was created
    if [ ! -f "$bpf_file" ]; then
        echo "✗ Error: BPF file not created"
        return 1
    fi

    echo "✓ BPF filter generated: $(ls -lh "$bpf_file" | awk '{print $5}')"

    # Remove the generator binary (we only need the BPF file)
    echo "Removing generator binary to save space..."
    rm -f "$output_dir/seccomp-unix-block"

    # Verify final state
    if [ -f "$bpf_file" ] && [ -f "$apply_seccomp_bin" ]; then
        echo "✓ Success: BPF filter and apply-seccomp binary ready for $vendor_dir"
        echo "  - BPF filter: $(ls -lh "$bpf_file" | awk '{print $5}')"
        echo "  - apply-seccomp: $(ls -lh "$apply_seccomp_bin" | awk '{print $5}')"
        return 0
    else
        if [ ! -f "$bpf_file" ]; then
            echo "✗ Error: BPF file not found in $output_dir"
        fi
        if [ ! -f "$apply_seccomp_bin" ]; then
            echo "✗ Error: apply-seccomp binary not found in $output_dir"
        fi
        return 1
    fi
}

# Build for all platforms
echo "Starting multi-platform seccomp binary builds..."
echo ""

FAILED_PLATFORMS=()

for platform_spec in "${PLATFORMS[@]}"; do
    IFS=':' read -r docker_platform vendor_dir base_image image_version <<< "$platform_spec"

    if ! build_platform "$docker_platform" "$vendor_dir" "$base_image" "$image_version"; then
        FAILED_PLATFORMS+=("$vendor_dir")
    fi
done

# Summary
echo ""
echo "=========================================="
echo "Build Summary"
echo "=========================================="

if [ ${#FAILED_PLATFORMS[@]} -eq 0 ]; then
    echo "✓ All platforms built successfully!"
    echo ""
    echo "Generated BPF filters:"
    find "$ROOT_DIR/vendor/seccomp" -name "*.bpf" | sort
    echo ""
    echo "Generated apply-seccomp binaries:"
    find "$ROOT_DIR/vendor/seccomp" -name "apply-seccomp" | sort
    echo ""
    echo "Total size:"
    du -sh "$ROOT_DIR/vendor/seccomp"
    echo ""
    echo "File sizes:"
    find "$ROOT_DIR/vendor/seccomp" \( -name "*.bpf" -o -name "apply-seccomp" \) -exec ls -lh {} \; | awk '{print $9 ": " $5}'
    exit 0
else
    echo "✗ Build failed for: ${FAILED_PLATFORMS[*]}"
    exit 1
fi
