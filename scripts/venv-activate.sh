#!/bin/bash

PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

if [ ! -d "$PROJECT_ROOT/.venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$PROJECT_ROOT/.venv"
fi

echo "Activating virtual environment..."
source "$PROJECT_ROOT/.venv/bin/activate"

echo "Venv activated at: $PROJECT_ROOT/.venv"
python3 --version
