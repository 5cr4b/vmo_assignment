# VMO Assignment

# Requirements
1. Given the attached python script, write some unit tests to ensure the script is working correctly. For generating sarif files for input
2. Create a workflow to run the unit test on PR creation. You may use any service provider (github/gitlab/jenkins) or even self hosted solutions.
3. Create a workflow to scan ubuntu:22.04 and alpine:latest using trivy, then upload the result to anywhere (sql, mongodb, etc)

# Aprroach 
- Create CI/CD pipeline on GitHub Action:
    - Use Trivy to scan container image (ubuntu:22.04 and alpine:latest)
    - Apply scan for PR creation
    - Create Python script to handle the result file (.sarif file), read, get and calculate the metadata from .sarif file
    - Write some unit tests to verify the Python script
    - Integrate Grafana/Kibana to view the result