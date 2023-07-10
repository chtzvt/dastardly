# Dastardly (With SARIF Support)

Welcome!

This is an extended version of PortSwigger's [Dastardly](https://github.com/PortSwigger/dastardly-github-action) action, with added support for the [Static Analysis Results Interchange Format (SARIF)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html). 

This repository wraps PortSwigger's base Dastardly action, adding a script that converts the JUnit XML produced by Dastardly into SARIF for [consumption](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning) by GitHub's Code Scanning tools.

### Usage

Adding the Dastardly SARIF action to your workflows is simple:

```yaml
  - uses: chtzvt/dastardly@v1
    with: 
        target-url: https://ginandjuice.shop/
        enable-sarif-report: true
```

### Inputs 

This action accepts the following inputs:

* **target-url:** The full url (including scheme) of the site to scan.

* **enable-junit-report:** Whether to enable the junit report. This will be uploaded as an artifact

* **enable-sarif-report:** Whether to enable the sarif report. This will be uploaded as a code scanning result

Extra options (you probably don't need to tweak these, but they're helpful for corner cases):

* **output-filename:** The filename used for the scan report. This filepath relates to the dastardly container, and will exist in the github workspace (/github/workspace)

* **upload-raw-report:** Whether to upload the raw Dastardly JUnit report as an artifact