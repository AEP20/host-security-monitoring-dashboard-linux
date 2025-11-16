#!/bin/bash

if [ -z "$VIRTUAL_ENV" ]; then
    echo "No virtual environment is currently active."
else
    echo "Deactivating virtual environment..."
    deactivate
fi
