# Dependabot Reporter

## Overview

Dependabot Reporter is a tool designed to generate reports based on Dependabot alerts. It helps you keep track of vulnerabilities and dependencies in your projects and share this information with your team or stakeholders.

## Features

- Generates detailed reports of Dependabot alerts.
- Supports multiple output formats (e.g., JSON, CSV).
- Easy to integrate into CI/CD pipelines.

## Installation

Make sure you have go installed. If not, you can download it from the https://go.dev/dl page.

Then you can install the tool by running the following commands.

```sh
# Clone the repository
git clone git@github.com:bubalubs/dependabot_reporter.git

# Change to the project directory
cd dependabot_reporter

# Setup the configuration file
cp config.yaml.example config.yaml

# Generate a report
go run . --repo=owner/repo
```

## Available Flags

```sh
go run . --repo=owner/repo --config=config.yaml --output=csv
```