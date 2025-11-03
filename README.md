# Web Vulnerability Scanner

An automated web vulnerability scanner with a modern web interface built with Flask and Tailwind CSS.

## Features

- **SQL Injection Detection**: Tests for SQL injection vulnerabilities
- **XSS Detection**: Identifies Cross-Site Scripting vulnerabilities
- **CSRF Protection Check**: Verifies CSRF protection in forms
- **Security Headers Analysis**: Checks for missing security headers
- **Sensitive File Discovery**: Scans for exposed sensitive files
- **Directory Listing Detection**: Identifies directory traversal issues
- **Information Disclosure**: Detects information leakage
- **Modern Web Interface**: Beautiful UI built with Tailwind CSS

## Installation

1. Install dependencies:
```bash
pip3 install -r requirements.txt
```

## Usage

### Web Interface

Start the Flask web server:
```bash
python3 app.py
```

Then open your browser and navigate to:
```
http://localhost:5000
```

Enter a target URL and click "Scan" to run a vulnerability scan.

### Command Line

You can also use the scanner directly from the command line:
```bash
python3 scanner.py <target_url> [-t timeout] [-o output_file]
```

Example:
```bash
python3 scanner.py http://example.com -o results.json
```

## Project Structure

- `scanner.py` - Core vulnerability scanner class
- `app.py` - Flask web application
- `templates/index.html` - Web interface (HTML with Tailwind CSS)
- `requirements.txt` - Python dependencies

## Security Note

This tool is for authorized security testing only. Only scan websites you own or have explicit permission to test.

