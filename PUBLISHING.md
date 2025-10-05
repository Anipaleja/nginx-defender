# nginx-defender Package Publishing Guide

This document explains how to publish the nginx-defender packages to npm, PyPI, and GitHub Packages.

## 📦 Available Packages

- **npm**: `@anipaleja/nginx-defender` - Node.js bindings
- **pip**: `nginx-defender` - Python bindings
- **go**: `github.com/Anipaleja/nginx-defender` - Go module

## 🚀 Quick Publish

### Option 1: Automated Script
```bash
./scripts/publish-packages.sh
```

### Option 2: Manual Publishing

#### npm Package
```bash
cd bindings/nodejs

# Login to npm (first time only)
npm login

# Install dependencies
npm install

# Publish to npm registry
npm publish --access public

# Publish to GitHub Packages (optional)
export NODE_AUTH_TOKEN=your_github_token
npm publish --registry=https://npm.pkg.github.com
```

#### Python Package
```bash
cd bindings/python

# Install build tools
pip install build twine

# Build package
python -m build

# Upload to PyPI
twine upload dist/*
```

## 🔧 Setup Requirements

### For npm Publishing
1. Create npm account at https://npmjs.com
2. Run `npm login` in terminal
3. Get GitHub Personal Access Token with `packages:write` scope (for GitHub Packages)

### For Python Publishing
1. Create PyPI account at https://pypi.org
2. Create API token in PyPI account settings
3. Install build tools: `pip install build twine`

## 📱 Using the Published Packages

### Node.js
```bash
npm install @anipaleja/nginx-defender
```

```javascript
const { NginxDefender } = require('@anipaleja/nginx-defender');

const defender = new NginxDefender();
await defender.start();
```

### Python
```bash
pip install nginx-defender
```

```python
from nginx_defender import NginxDefender

defender = NginxDefender()
defender.start()
```

### Go
```bash
go get github.com/Anipaleja/nginx-defender
```

```go
import "github.com/Anipaleja/nginx-defender/pkg/defender"

defender := defender.NewDefender()
defender.Start()
```

## 🔐 Authentication Tokens

You'll need to set up these secrets in your repository for automated publishing:

- `NPM_TOKEN`: npm registry token
- `PYPI_API_TOKEN`: PyPI API token  
- `GITHUB_TOKEN`: Automatically provided by GitHub Actions

## 🏷️ Version Management

Update versions in these files before publishing:
- `bindings/nodejs/package.json`
- `bindings/python/pyproject.toml`
- `bindings/python/src/nginx_defender/__init__.py`

## 🚨 Troubleshooting

### npm publish fails
```bash
# Check login status
npm whoami

# Check package name availability
npm info @anipaleja/nginx-defender

# Fix permissions
npm publish --access public
```

### Python publish fails
```bash
# Check if package exists on PyPI
curl -s https://pypi.org/pypi/nginx-defender/json | jq '.info.version' || echo "Package not found"

# Or visit https://pypi.org/project/nginx-defender/ in browser

# List available versions (if package exists)
pip index versions nginx-defender

# Validate package
twine check dist/*

# Use API token instead of password
twine upload -u __token__ -p your_api_token dist/*
```

## 📋 Pre-publish Checklist

- [ ] Update version numbers
- [ ] Update CHANGELOG.md
- [ ] Run tests (`npm test`, `python -m pytest`)
- [ ] Build packages successfully
- [ ] Check package contents
- [ ] Verify authentication tokens
- [ ] Test installation locally

## 🔄 Automated Publishing

The `.github/workflows/publish-packages.yml` workflow automatically publishes packages when you create a git tag:

```bash
git tag v2.0.1
git push origin v2.0.1
```

This will trigger the workflow to publish all packages automatically.
