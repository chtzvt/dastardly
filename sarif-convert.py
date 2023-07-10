import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urlunparse
import hashlib
import json
import re

# Parse XML tree
tree = ET.parse('dastardly-report.xml')
root = tree.getroot()

# Initialize SARIF schema
sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": []
}

# Convert Dastardly severity to SARIF problem severity
def sarif_problem_severity(s):
    return {
        "High": "error",
        "Medium": "warning",
        "Low": "note",
        "Information": "none"
    }.get(s, "none")

# Convert Dastardly severity to SARIF security severity
def sarif_security_severity(s):
    return {
        "High": "7.0",
        "Medium": "4.0",
        "Low": "1.0",
        "Information": "0.0"
    }.get(s, "1.0")


# Define a run
run = {
    "tool": {
        "driver": {
            "name": "Dastardly",
            "version": "1.0",
            "informationUri": "https://portswigger.net/burp/dastardly",
            "rules": []
        }
    },
    "originalUriBaseIds": {
        "target": {
            "uri": "PLACEHOLDER",
            "description": {
                "text": "The base URI for all Dastardly scan artifacts."
            }
        }
    },
    "results": [] 
}

rule_index = 0

# Iterate over Dastardly results (testsuites)
for suite in root.findall('testsuite'):

    # If this is the first testsuite, set the uri
    if run['originalUriBaseIds']['target']['uri'] == "PLACEHOLDER":
        parsed_url = urlparse(suite.attrib['name'])
        stripped_url = urlunparse((parsed_url.scheme, parsed_url.netloc, '', '', parsed_url.query, ''))
        run['originalUriBaseIds']['target']['uri'] = stripped_url + "/"

    # Skip current testsuite if there are no failures
    if int(suite.attrib['failures']) == 0:
        continue

    # Iterate through testcases
    for case in suite.findall('testcase'):
        failure = case.find('failure')
        if failure is None:
            continue

        severity = case.attrib.get('type', '')  
        # Create a unique ID for the rule
        rule_id = hashlib.md5(bytes(suite.attrib['name'] + failure.attrib['message'], 'utf-8')).hexdigest()

        # Define a rule
        rule = {
            "id": rule_id,
            "shortDescription": {
                "text": failure.attrib['message']
            },
            "help": {
                "text": failure.attrib['message'],
                "markdown": "# " + failure.attrib['message']
            },
            "properties": {
                "impact": [failure.attrib['message']],
                "problem.severity": sarif_problem_severity(severity),
                "resolution": [failure.attrib['message']],
                "security-severity": sarif_security_severity(severity)
            }
        }

        # Get the severity of the failure
        severity_failure = failure.attrib.get('type', '')
        stripped_text = failure.text.strip()
        # Update the properties of the rule
        rule['help']['text'] = stripped_text
        rule['help']['markdown'] = stripped_text
        rule['properties']['impact'] = [stripped_text]
        rule['properties']['resolution'] = [stripped_text]
        rule['properties']['problem.severity'] = sarif_problem_severity(severity_failure)
        rule['properties']['security-severity'] = sarif_security_severity(severity_failure)

        # Add the rule to the run
        run['tool']['driver']['rules'].append(rule) 

        parsed_url = urlparse(suite.attrib['name'])
        
        # Define a result
        result = {
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": sarif_problem_severity(severity_failure),
            "message": {
                "text": failure.attrib['message']
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": urlunparse(("", "", parsed_url.path.lstrip('/'), parsed_url.params, parsed_url.query, parsed_url.fragment)),
                            "uriBaseId": "target"
                        }
                    }
                }
            ],
            "hostedViewerUri": suite.attrib['name']
        }

        run['results'].append(result) 

        rule_index += 1 

sarif['runs'].append(run)

with open('output.sarif', 'w') as f:
    json.dump(sarif, f, indent=4)