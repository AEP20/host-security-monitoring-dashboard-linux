#!/bin/bash

# Go to project root based on script location
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

# If .venv doesn't exist, create it
if [ ! -d "$PROJECT_ROOT/.venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$PROJECT_ROOT/.venv"
fi

# Activate venv
echo "Activating virtual environment..."
source "$PROJECT_ROOT/.venv/bin/activate"

# Show Python version and venv path
echo "Venv activated at: $PROJECT_ROOT/.venv"
python3 --version
