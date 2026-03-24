#!/bin/bash
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

echo "Installing dependencies..."
pip install -q -r requirements.txt

if [ ! -f "static/icons/icon-192.png" ]; then
    echo "Generating app icons..."
    python generate_icons.py
fi

echo ""
python server.py
