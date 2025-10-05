#!/bin/bash

# nginx-defender Package Publishing Script
# This script helps publish the packages to npm and PyPI

set -e

echo "🚀 nginx-defender Package Publisher"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [[ ! -f "go.mod" ]] || [[ ! -d "bindings" ]]; then
    print_error "Please run this script from the nginx-defender root directory"
    exit 1
fi

# Function to publish npm package
publish_npm() {
    print_status "Publishing npm package..."
    
    cd bindings/nodejs
    
    # Check if logged in to npm
    if ! npm whoami > /dev/null 2>&1; then
        print_warning "You are not logged in to npm. Please run:"
        echo "npm login"
        exit 1
    fi
    
    # Install dependencies and build
    print_status "Installing dependencies..."
    npm install
    
    # Check if a real build script exists by inspecting package.json
    if command -v jq &> /dev/null; then
        build_script=$(jq -r '.scripts.build // empty' package.json 2>/dev/null)
    else
        # Fallback to node if jq not available
        build_script=$(node -e "try { console.log(require('./package.json').scripts.build || ''); } catch(e) { console.log(''); }" 2>/dev/null)
    fi
    
    # Skip if no build script or it's a no-op command
    if [[ -z "$build_script" ]]; then
        print_status "Skipping build step (no build script found)"
    else
        # Normalize and trim the build script
        normalized_script=$(echo "$build_script" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')
        
        # Check for common no-op patterns using regex
        if [[ "$normalized_script" =~ ^echo[[:space:]]+[\'\""].*[\'\""]?$ ]] || \
           [[ "$normalized_script" =~ ^true[[:space:]]*$ ]] || \
           [[ "$normalized_script" =~ ^:[[:space:]]*$ ]] || \
           [[ -z "$normalized_script" ]]; then
            print_status "Skipping build step (no-op command detected: $normalized_script)"
        else
            print_status "Building package..."
            npm run build
        fi
    fi
    
    # Check if test script exists without running it
    if command -v jq &> /dev/null; then
        test_script=$(jq -r '.scripts.test // empty' package.json 2>/dev/null)
    else
        # Fallback to node if jq not available
        test_script=$(node -e "try { console.log(require('./package.json').scripts.test || ''); } catch(e) { console.log(''); }" 2>/dev/null)
    fi
    
    if [[ -n "$test_script" ]]; then
        print_status "Running tests..."
        npm test
    else
        print_status "No test script found, skipping tests"
    fi
    
    # Publish to npm
    print_status "Publishing to npm registry..."
    npm publish --access public
    
    print_status "✅ npm package published successfully!"
    
    cd ../..
}

# Function to publish Python package
publish_python() {
    print_status "Publishing Python package..."
    
    cd bindings/python
    
    # Check if twine is installed
    if ! command -v twine &> /dev/null; then
        print_status "Installing twine..."
        pip install twine build
    fi
    
    # Clean previous builds
    rm -rf dist/ build/ *.egg-info/
    
    # Build package
    print_status "Building Python package..."
    python -m build
    
    # Check package
    print_status "Checking package..."
    twine check dist/*
    
    # Upload to PyPI
    print_status "Uploading to PyPI..."
    print_warning "You'll need to enter your PyPI credentials or API token"
    twine upload dist/*
    
    print_status "✅ Python package published successfully!"
    
    cd ../..
}

# Function to setup GitHub Packages
setup_github_packages() {
    print_status "Setting up GitHub Packages..."
    
    cd bindings/nodejs
    
    # Backup existing .npmrc if it exists with proper error handling
    if [[ -f .npmrc ]]; then
        backup_file=".npmrc.backup.$(date +%s)"
        print_status "Backing up existing .npmrc to $backup_file"
        
        if ! cp .npmrc "$backup_file"; then
            print_error "Failed to backup .npmrc file"
            exit 1
        fi
        
        # Remove existing registry entries using a safe temp file
        temp_file=$(mktemp) || {
            print_error "Failed to create temporary file"
            exit 1
        }
        
        # Ensure temp file cleanup on exit
        trap 'rm -f "$temp_file"' EXIT
        
        # Remove existing @anipaleja registry lines using sed with error checking
        if ! sed -E '/^@anipaleja:registry=/d; /^\/\/npm\.pkg\.github\.com\/:_authToken=/d' .npmrc > "$temp_file"; then
            print_error "Failed to process .npmrc file"
            rm -f "$temp_file"
            exit 1
        fi
        
        # Atomically replace the original file
        if ! mv "$temp_file" .npmrc; then
            print_error "Failed to update .npmrc file"
            exit 1
        fi
    fi
    
    # Append GitHub Packages configuration
    cat >> .npmrc << EOF
@anipaleja:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=\${NODE_AUTH_TOKEN}
EOF
    
    print_status "Created .npmrc for GitHub Packages"
    print_warning "To publish to GitHub Packages, set NODE_AUTH_TOKEN environment variable:"
    echo "export NODE_AUTH_TOKEN=your_github_token"
    echo "npm publish"
    
    cd ../..
}

# Main menu
echo ""
echo "Select an option:"
echo "1) Publish npm package to npm registry"
echo "2) Publish Python package to PyPI"
echo "3) Setup GitHub Packages configuration"
echo "4) Publish both packages"
echo "5) Exit"
echo ""

read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        publish_npm
        ;;
    2)
        publish_python
        ;;
    3)
        setup_github_packages
        ;;
    4)
        publish_npm
        publish_python
        ;;
    5)
        print_status "Exiting..."
        exit 0
        ;;
    *)
        print_error "Invalid option"
        exit 1
        ;;
esac

print_status "🎉 Publishing completed!"
