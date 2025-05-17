#!/bin/bash
set -e

echo "🔧 Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "📦 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements-dev.txt

echo "✅ Setup complete. To activate your environment:"
echo "source venv/bin/activate"
