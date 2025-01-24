#!/bin/bash

# Exit on error
set -e

echo "Starting setup process..."

# Check if conda is installed
if ! command -v conda &> /dev/null; then
    echo "Error: conda is not installed. Please install conda first."
    exit 1
fi

# Create conda environment from environment.yml
echo "Creating conda environment 'iris' from environment.yml..."
if [ ! -f "environment.yml" ]; then
    echo "Error: environment.yml not found in current directory"
    exit 1
fi

# Remove existing environment if it exists
conda env remove -n iris 2>/dev/null || true

# Create new environment
conda env create -f environment.yml

# Create necessary directories
echo "Creating directories..."
mkdir -p "../codeql"
mkdir -p "../data/codeql-dbs"

# Download CodeQL zip file
echo "Downloading patched CodeQL..."
CODEQL_URL="https://github.com/seal-research/iris/releases/download/codeql-0.8.3-patched/codeql.zip"
CODEQL_ZIP="codeql.zip"

if ! curl -L -o "$CODEQL_ZIP" "$CODEQL_URL"; then
    echo "Error: Failed to download CodeQL"
    exit 1
fi

# Unzip CodeQL
echo "Extracting CodeQL..."
if ! unzip -q "$CODEQL_ZIP" -d "../codeql"; then
    echo "Error: Failed to extract CodeQL"
    rm -f "$CODEQL_ZIP"
    exit 1
fi

# Clean up zip file
rm -f "$CODEQL_ZIP"

echo "Setup completed successfully!"
echo "- Conda environment 'iris' has been created"
echo "- CodeQL has been downloaded and extracted to '../codeql'"
echo "- Created '../data/codeql-dbs' directory"
echo ""
echo "To activate the environment, run: conda activate iris"