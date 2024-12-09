import pytest
from sarif_analyzer import SarifAnalyzer
import json
from pathlib import Path

@pytest.fixture
def sample_sarif_data():
    return {
        "runs": [{
            "results": [
                {"level": "error"},
                {"level": "warning"},
                {"level": "warning"},
                {"level": "note"}
            ],
            "tool": {
                "driver": {
                    "rules": [
                        {"id": "rule1"},
                        {"id": "rule2"}
                    ]
                }
            }
        }]
    }

@pytest.fixture
def sample_sarif_file(sample_sarif_data):
    file_path = "report.sarif"
    with open(file_path, "w") as f:
        json.dump(sample_sarif_data, f)
    return str(file_path)

def test_read_sarif_file(sample_sarif_file, sample_sarif_data):
    analyzer = SarifAnalyzer([sample_sarif_file])
    result = analyzer.read_sarif_file(sample_sarif_file)
    assert result == sample_sarif_data

def test_calculate_severity_metrics(sample_sarif_data):
    analyzer = SarifAnalyzer([])
    metrics = analyzer.calculate_severity_metrics(sample_sarif_data)
    assert metrics == {
        "error": 1,
        "warning": 2,
        "note": 1
    }

def test_analyze_vulnerabilities(sample_sarif_file):
    analyzer = SarifAnalyzer([sample_sarif_file])
    analysis = analyzer.analyze_vulnerabilities()
    
    assert sample_sarif_file in analysis
    metrics = analysis[sample_sarif_file]
    
    assert metrics['total_findings'] == 4
    assert metrics['rules_evaluated'] == 2
    assert metrics['severity_metrics'] == {
        "error": 1,
        "warning": 2,
        "note": 1
    }

def test_generate_summary(sample_sarif_file):
    analyzer = SarifAnalyzer([sample_sarif_file])
    summary = analyzer.generate_summary()
    
    assert "Total findings: 4" in summary
    assert "Rules evaluated: 2" in summary
    assert "error: 1" in summary
    assert "warning: 2" in summary
    assert "note: 1" in summary
