# Dependabot Reporter

## Overview

Dependabot Reporter is a tool designed to generate reports based on Dependabot alerts. It helps you keep track of vulnerabilities and dependencies in your projects and share this information with your team or stakeholders.

## Features

- Generates detailed reports of Dependabot alerts.
- Supports multiple output formats (e.g., JSON, CSV).
- Easy to integrate into CI/CD pipelines.

## Installation

Clone the repository and build the binary:

```sh
git clone git@github.com:bubalubs/dependabot_reporter.git
cd dependabot_reporter
touch config.yaml
go run . --repo=owner/repo
```
