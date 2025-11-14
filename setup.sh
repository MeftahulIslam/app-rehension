#!/bin/bash

echo "🛡️  Security Assessor - Setup Script"
echo "===================================="
echo ""

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python version: $python_version"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo "✓ Dependencies installed"

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found"
    echo "📝 Creating .env from template..."
    cp .env.example .env
    echo "⚠️  IMPORTANT: Please edit .env and add your API keys:"
    echo "   - GEMINI_API_KEY (required)"
    echo "   - PRODUCTHUNT_API_KEY (optional)"
    echo ""
    echo "Get your Gemini API key from: https://makersuite.google.com/app/apikey"
    echo ""
else
    echo "✓ .env file exists"
    
    # Check if API keys are set
    if grep -q "your_gemini_api_key_here" .env; then
        echo "⚠️  WARNING: GEMINI_API_KEY not configured in .env"
        echo "   Please add your API key to continue"
    else
        echo "✓ GEMINI_API_KEY configured"
    fi
fi

echo ""
echo "===================================="
echo "✅ Setup complete!"
echo ""
echo "To start the application:"
echo "  1. Make sure your API keys are set in .env"
echo "  2. Run: source venv/bin/activate"
echo "  3. Run: python app.py"
echo "  4. Open: http://localhost:5000"
echo ""
echo "For more information, see README.md"
echo "===================================="
