# KMS Key Permissions Report Script

This Bash script generates a report of AWS Identity and Access Management (IAM) role permissions related to AWS Key Management Service (KMS) keys in your AWS account. The script checks both Multi-Region and Single-Region KMS keys to identify which IAM roles have access to them and what specific actions are allowed.

## Features

- Generates a CSV report listing IAM roles, policies (inline and attached), KMS key ARNs, and the specific permissions/actions granted.
- Supports both Multi-Region and Single-Region KMS keys.
- Automatically timestamps the report filename for easy tracking.

## Prerequisites

Before running this script, ensure you have the following:

1. **AWS CLI**: Installed and configured with appropriate access to list IAM roles, policies, and KMS keys.
2. **JQ**: Installed to parse JSON outputs from AWS CLI commands.

### Installation of Prerequisites

- AWS CLI: [AWS CLI Installation Guide](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)
- JQ: [JQ Installation Guide](https://stedolan.github.io/jq/download/)

## Usage

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/your-repo-name.git
   cd your-repo-name
