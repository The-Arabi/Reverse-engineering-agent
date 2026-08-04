"""
Web Dashboard for Enhanced Knowledge Base
Provides REST API and simple web interface
"""

import os
import json
from flask import Flask, request, jsonify, render_template_string, Response
from flask_cors import CORS
import logging
from knowledge_base_enhanced import enhanced_kb, KnowledgeType, add_fact, add_hypothesis, add_experiment

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("web_dashboard")

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend access

# HTML template for simple web interface
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Reverse Engineering Knowledge Base Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; }
        .section { border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, textarea, select { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 3px; }
        button { background-color: #007cba; color: white; padding: 10px 15px; border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background-color: #005a87; }
        .results { background-color: #f9f9f9; padding: 15px; border-radius: 3px; margin-top: 10px; }
        .stats { display: flex; gap: 20px; flex-wrap: wrap; }
        .stat-box { border: 1px solid #eee; padding: 15px; border-radius: 5px; flex: 1; min-width: 200px; }
        .tab { overflow: hidden; border: 1px solid #ccc; background-color: #f1f1f1; }
        .tab button { background-color: inherit; float: left; border: none; outline: none; cursor: pointer; padding: 14px 16px; transition: 0.3s; }
        .tab button:hover { background-color: #ddd; }
        .tab button.active { background-color: #ccc; }
        .tabcontent { display: none; padding: 20px; border-top: none; }
        .knowledge-item { border: 1px solid #eee; padding: 15px; margin-bottom: 10px; border-radius: 3px; }
        .item-type { display: inline-block; padding: 2px 6px; background: #007cba; color: white; border-radius: 3px; font-size: 0.8em; margin-right: 10px; }
        .confidence { font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Reverse Engineering Knowledge Base Dashboard</h1>
            <p>Multi-backend knowledge storage system</p>
        </div>

        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'View')">View Knowledge</button>
            <button class="tablinks" onclick="openTab(event, 'Add')">Add Knowledge</button>
            <button class="tablinks" onclick="openTab(event, 'Stats')">Statistics</button>
        </div>

        <div id="View" class="tabcontent" style="display: block;">
            <div class="section">
                <h2>Knowledge Items</h2>
                <div class="form-group">
                    <label for="searchQuery">Search:</label>
                    <input type="text" id="searchQuery" placeholder="Search by title or description...">
                    <button onclick="searchKnowledge()">Search</button>
                    <button onclick="loadAllKnowledge()">Show All</button>
                </div>
                <div id="knowledgeResults" class="results"></div>
            </div>
        </div>

        <div id="Add" class="tabcontent">
            <div class="section">
                <h2>Add New Fact</h2>
                <div class="form-group">
                    <label for="factTitle">Title:</label>
                    <input type="text" id="factTitle" placeholder="Enter fact title">
                </div>
                <div class="form-group">
                    <label for="factDescription">Description:</label>
                    <textarea id="factDescription" rows="4" placeholder="Enter fact description"></textarea>
                </div>
                <div class="form-group">
                    <label for="factConfidence">Confidence (0.0-1.0):</label>
                    <input type="number" id="factConfidence" min="0" max="1" step="0.1" value="0.8">
                </div>
                <div class="form-group">
                    <label for="factTags">Tags (comma-separated):</label>
                    <input type="text" id="factTags" placeholder="e.g., firmware, vulnerability, buffer-overflow">
                </div>
                <button onclick="addFact()">Add Fact</button>
                <div id="factResult" class="results"></div>
            </div>

            <div class="section">
                <h2>Add New Hypothesis</h2>
                <div class="form-group">
                    <label for="hypTitle">Title:</label>
                    <input type="text" id="hypTitle" placeholder="Enter hypothesis title">
                </div>
                <div class="form-group">
                    <label for="hypDescription">Description:</label>
                    <textarea id="hypDescription" rows="4" placeholder="Enter hypothesis description"></textarea>
                </div>
                <div class="form-group">
                    <label for="hypConfidence">Confidence (0.0-1.0):</label>
                    <input type="number" id="hypConfidence" min="0" max="1" step="0.1" value="0.5">
                </div>
                <div class="form-group">
                    <label for="hypBasis">Basis:</label>
                    <input type="text" id="hypBasis" placeholder="What led to this hypothesis">
                </div>
                <div class="form-group">
                    <label for="hypTestable">Testable:</label>
                    <select id="hypTestable">
                        <option value="true">Yes</option>
                        <option value="false">No</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="hypPrediction">Prediction:</label>
                    <input type="text" id="hypPrediction" placeholder="What would happen if true">
                </div>
                <div class="form-group">
                    <label for="hypFalsification">Falsification Condition:</label>
                    <input type="text" id="hypFalsification" placeholder="What would prove it false">
                </div>
                <button onclick="addHypothesis()">Add Hypothesis</button>
                <div id="hypResult" class="results"></div>
            </div>
        </div>

        <div id="Stats" class="tabcontent">
            <div class="section">
                <h2>Knowledge Base Statistics</h2>
                <div id="statsDisplay" class="stats"></div>
                <button onclick="refreshStats()">Refresh Statistics</button>
            </div>
        </div>
    </div>

    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }

        function loadAllKnowledge() {
            fetch('/api/knowledge')
                .then(response => response.json())
                .then(data => {
                    displayKnowledgeResults(data);
                })
                .catch(error => {
                    document.getElementById('knowledgeResults').innerHTML = '<p class="error">Error loading knowledge: ' + error + '</p>';
                });
        }

        function searchKnowledge() {
            const query = document.getElementById('searchQuery').value;
            fetch(`/api/knowledge/search?q=${encodeURIComponent(query)}`)
                .then(response => response.json())
                .then(data => {
                    displayKnowledgeResults(data);
                })
                .catch(error => {
                    document.getElementById('knowledgeResults').innerHTML = '<p class="error">Error searching knowledge: ' + error + '</p>';
                });
        }

        function displayKnowledgeResults(items) {
            const container = document.getElementById('knowledgeResults');
            if (!items || items.length === 0) {
                container.innerHTML = '<p>No knowledge items found.</p>';
                return;
            }

            let html = '';
            items.forEach(item => {
                html += `
                    <div class="knowledge-item">
                        <span class="item-type">${item.type}</span>
                        <h3>${item.title}</h3>
                        <p>${item.description}</p>
                        <p><span class="confidence">Confidence:</span> ${item.confidence.toFixed(2)}</p>
                        <p><span class="confidence">Tags:</span> ${item.tags.join(', ') || 'None'}</p>
                        <p><small>Created: ${new Date(item.created_at).toLocaleString()}</small></p>
                    </div>
                `;
            });
            container.innerHTML = html;
        }

        function addFact() {
            const title = document.getElementById('factTitle').value.trim();
            const description = document.getElementById('factDescription').value.trim();
            const confidence = parseFloat(document.getElementById('factConfidence').value);
            const tagsInput = document.getElementById('factTags').value.trim();
            const tags = tagsInput ? tagsInput.split(',').map(t => t.trim()) : [];

            if (!title || !description) {
                document.getElementById('factResult').innerHTML = '<p class="error">Title and description are required</p>';
                return;
            }

            fetch('/api/fact', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    title: title,
                    description: description,
                    confidence: confidence,
                    tags: tags
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('factResult').innerHTML = `<p class="success">Fact added successfully! ID: ${data.id}</p>`;
                    // Clear form
                    document.getElementById('factTitle').value = '';
                    document.getElementById('factDescription').value = '';
                    document.getElementById('factConfidence').value = '0.8';
                    document.getElementById('factTags').value = '';
                } else {
                    document.getElementById('factResult').innerHTML = `<p class="error">Error: ${data.error}</p>`;
                }
            })
            .catch(error => {
                document.getElementById('factResult').innerHTML = `<p class="error">Error adding fact: ${error}</p>`;
            });
        }

        function addHypothesis() {
            const title = document.getElementById('hypTitle').value.trim();
            const description = document.getElementById('hypDescription').value.trim();
            const confidence = parseFloat(document.getElementById('hypConfidence').value);
            const basis = document.getElementById('hypBasis').value.trim();
            const testable = document.getElementById('hypTestable').value === 'true';
            const prediction = document.getElementById('hypPrediction').value.trim();
            const falsification = document.getElementById('hypFalsification').value.trim();

            if (!title || !description || !basis || !prediction || !falsification) {
                document.getElementById('hypResult').innerHTML = '<p class="error">All fields are required</p>';
                return;
            }

            fetch('/api/hypothesis', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    title: title,
                    description: description,
                    confidence: confidence,
                    basis: basis,
                    testable: testable,
                    prediction: prediction,
                    falsification_condition: falsification
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('hypResult').innerHTML = `<p class="success">Hypothesis added successfully! ID: ${data.id}</p>`;
                    // Clear form
                    document.getElementById('hypTitle').value = '';
                    document.getElementById('hypDescription').value = '';
                    document.getElementById('hypConfidence').value = '0.5';
                    document.getElementById('hypBasis').value = '';
                    document.getElementById('hypPrediction').value = '';
                    document.getElementById('hypFalsification').value = '';
                } else {
                    document.getElementById('hypResult').innerHTML = `<p class="error">Error: ${data.error}</p>`;
                }
            })
            .catch(error => {
                document.getElementById('hypResult').innerHTML = `<p class="error">Error adding hypothesis: ${error}</p>`;
            });
        }

        function refreshStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    displayStats(data);
                })
                .catch(error => {
                    document.getElementById('statsDisplay').innerHTML = `<p class="error">Error loading stats: ${error}</p>`;
                });
        }

        function displayStats(stats) {
            const container = document.getElementById('statsDisplay');
            let html = '';

            if (stats.backends) {
                for (const [backend, info] of Object.entries(stats.backends)) {
                    if (info.error) {
                        html += `<div class="stat-box"><h3>${backend}</h3><p class="error">Error: ${info.error}</p></div>`;
                    } else {
                        html += `<div class="stat-box"><h3>${backend.charAt(0).toUpperCase() + backend.slice(1)}</h3>`;
                        if (info.count !== undefined) {
                            html += `<p>Total Items: ${info.count}</p>`;
                        }
                        if (info.vector_enabled !== undefined) {
                            html += `<p>Vector Search: ${info.vector_enabled ? 'Enabled' : 'Disabled'}</p>`;
                        }
                        if (info.used_memory) {
                            html += `<p>Memory Used: ${info.used_memory}</p>`;
                        }
                        html += `</div>`;
                    }
                }
            } else {
                html = '<p>No statistics available</p>';
            }

            container.innerHTML = html;
        }

        // Load initial data
        window.onload = function() {
            loadAllKnowledge();
            refreshStats();
        };
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Serve the main dashboard page"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/knowledge')
def get_knowledge():
    """Get all knowledge items"""
    try:
        limit = request.args.get('limit', 50, type=int)
        items = enhanced_kb.search_knowledge_light(limit=limit)
        return jsonify([{
            'id': item.id,
            'type': item.type.value,
            'title': item.title,
            'description': item.description,
            'confidence': item.confidence,
            'tags': item.tags,
            'created_at': item.created_at,
            'updated_at': item.updated_at
        } for item in items])
    except Exception as e:
        logger.error(f"Error getting knowledge: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/knowledge/search')
def search_knowledge():
    """Search knowledge items"""
    try:
        query = request.args.get('q', '')
        limit = request.args.get('limit', 20, type=int)
        items = enhanced_kb.search_knowledge_light(query=query, limit=limit)
        return jsonify([{
            'id': item.id,
            'type': item.type.value,
            'title': item.title,
            'description': item.description,
            'confidence': item.confidence,
            'tags': item.tags,
            'created_at': item.created_at,
            'updated_at': item.updated_at
        } for item in items])
    except Exception as e:
        logger.error(f"Error searching knowledge: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/fact', methods=['POST'])
def add_fact_endpoint():
    """Add a new fact"""
    try:
        data = request.get_json()
        fact_id = add_fact(
            title=data.get('title', ''),
            description=data.get('description', ''),
            confidence=float(data.get('confidence', 0.5)),
            evidence=data.get('evidence', []),
            source_references=data.get('source_references', []),
            tags=data.get('tags', []),
            source_agent=data.get('source_agent', 'web_dashboard')
        )
        return jsonify({'success': True, 'id': fact_id})
    except Exception as e:
        logger.error(f"Error adding fact: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/hypothesis', methods=['POST'])
def add_hypothesis_endpoint():
    """Add a new hypothesis"""
    try:
        data = request.get_json()
        hypothesis_id = add_hypothesis(
            title=data.get('title', ''),
            description=data.get('description', ''),
            confidence=float(data.get('confidence', 0.5)),
            basis=data.get('basis', ''),
            testable=bool(data.get('testable', False)),
            prediction=data.get('prediction', ''),
            falsification_condition=data.get('falsification_condition', ''),
            tags=data.get('tags', []),
            source_agent=data.get('source_agent', 'web_dashboard')
        )
        return jsonify({'success': True, 'id': hypothesis_id})
    except Exception as e:
        logger.error(f"Error adding hypothesis: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/experiment', methods=['POST'])
def add_experiment_endpoint():
    """Add a new experiment"""
    try:
        data = request.get_json()
        experiment_id = add_experiment(
            title=data.get('title', ''),
            description=data.get('description', ''),
            confidence=float(data.get('confidence', 0.5)),
            hypothesis_id=data.get('hypothesis_id', ''),
            setup=data.get('setup', ''),
            procedure=data.get('procedure', ''),
            results=data.get('results', ''),
            conclusion=data.get('conclusion', ''),
            tags=data.get('tags', []),
            source_agent=data.get('source_agent', 'web_dashboard')
        )
        return jsonify({'success': True, 'id': experiment_id})
    except Exception as e:
        logger.error(f"Error adding experiment: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/stats')
def get_stats():
    """Get knowledge base statistics"""
    try:
        stats = enhanced_kb.get_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': str(os.times())})


@app.route('/metrics')
def metrics_endpoint():
    """Prometheus metrics endpoint.
    Returns all collected metrics in Prometheus text exposition format.
    """
    try:
        from monitoring import get_metrics
        collector = get_metrics()
        metrics_text = collector.expose_prometheus()
        return Response(metrics_text, mimetype="text/plain; version=0.0.4; charset=utf-8")
    except Exception as e:
        logger.error(f"Error generating metrics: {e}")
        return Response(f"# Error generating metrics: {e}\n", mimetype="text/plain", status=500)


@app.route('/api/metrics')
def metrics_json_endpoint():
    """JSON metrics endpoint for API consumption."""
    try:
        from monitoring import get_metrics
        collector = get_metrics()
        return jsonify(collector.expose_json())
    except Exception as e:
        logger.error(f"Error generating JSON metrics: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Get configuration from environment
    host = os.getenv('DASHBOARD_HOST', '0.0.0.0')
    port = int(os.getenv('DASHBOARD_PORT', 5000))
    debug = os.getenv('DASHBOARD_DEBUG', 'False').lower() == 'true'

    logger.info(f"Starting web dashboard on {host}:{port}")
    app.run(host=host, port=port, debug=debug)