#!/usr/bin/env python3
"""
Flask Web Application for Vulnerability Scanner
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from scanner import VulnerabilityScanner
import traceback

app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    """Render the main UI"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    """API endpoint to run vulnerability scan"""
    try:
        data = request.get_json()
        target_url = data.get('url', '').strip()
        timeout = int(data.get('timeout', 10))
        
        if not target_url:
            return jsonify({
                'success': False,
                'error': 'Target URL is required'
            }), 400
        
        # Validate URL format
        if not (target_url.startswith('http://') or target_url.startswith('https://')):
            target_url = 'http://' + target_url
        
        # Create scanner and run scan
        scanner = VulnerabilityScanner(target_url, timeout=timeout)
        results = scanner.scan()
        
        return jsonify({
            'success': True,
            'results': results
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)

