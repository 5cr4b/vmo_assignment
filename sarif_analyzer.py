import json
import sys
from collections import defaultdict
from typing import Dict, List, Any

class SarifAnalyzer:
    def __init__(self, sarif_files: List[str]):
        self.sarif_files = sarif_files
        self.results = {}

    def read_sarif_file(self, file_path: str) -> Dict[str, Any]:
        """Read and parse a SARIF file."""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading SARIF file {file_path}: {e}")
            return {}

    def calculate_severity_metrics(self, data: Dict[str, Any]) -> Dict[str, int]:
        """Calculate metrics by severity level."""
        severity_counts = defaultdict(int)
        
        for run in data.get('runs', []):
            for result in run.get('results', []):
                severity = result.get('level', 'none')
                severity_counts[severity] += 1
                
        return dict(severity_counts)

    def analyze_vulnerabilities(self) -> Dict[str, Any]:
        """Analyze vulnerabilities from all SARIF files."""
        all_metrics = {}
        
        for file_path in self.sarif_files:
            sarif_data = self.read_sarif_file(file_path)
            if not sarif_data:
                continue
                
            metrics = {
                'severity_metrics': self.calculate_severity_metrics(sarif_data),
                'total_findings': len(sarif_data.get('runs', [{}])[0].get('results', [])),
                'rules_evaluated': len(sarif_data.get('runs', [{}])[0].get('tool', {}).get('driver', {}).get('rules', [])),
            }
            
            all_metrics[file_path] = metrics
            
        return all_metrics

    def generate_summary(self) -> str:
        """Generate a human-readable summary of the analysis."""
        summary = []
        analysis = self.analyze_vulnerabilities()
        
        for file_path, metrics in analysis.items():
            summary.append(f"\nResults for {file_path}:")
            summary.append(f"Total findings: {metrics['total_findings']}")
            summary.append(f"Rules evaluated: {metrics['rules_evaluated']}")
            summary.append("\nSeverity breakdown:")
            
            for severity, count in metrics['severity_metrics'].items():
                summary.append(f"- {severity}: {count}")
                
        return "\n".join(summary)

def main():
    if len(sys.argv) < 2:
        print("Usage: python sarif_analyzer.py <sarif_file1> [sarif_file2 ...]")
        sys.exit(1)
        
    analyzer = SarifAnalyzer(sys.argv[1:])
    print(analyzer.generate_summary())

if __name__ == "__main__":
    main()