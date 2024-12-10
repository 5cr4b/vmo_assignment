import json
import sys
from collections import defaultdict

class SarifAnalyzer:
    def __init__(self, sarif_files):
        self.sarif_files = sarif_files
        self.results = {}

    def read_sarif_file(self, file_path):
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading SARIF file {file_path}: {e}")
            return {}

    def calculate_severity_metrics(self, data):
        severity_counts = defaultdict(int)
        
        for run in data.get('runs', []):
            for result in run.get('results', []):
                severity = result.get('level', 'none')
                severity_counts[severity] += 1
                
        return dict(severity_counts)

    def analyze_vulnerabilities(self):
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

    def generate_summary(self):
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
    analyzer = SarifAnalyzer(sys.argv[1:])
    print(analyzer.generate_summary())

if __name__ == "__main__":
    main()