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
   ```

2. **Update the Script:**

   - Replace `YOUR_ACCOUNT_ID` and `YOUR_REGION` with your actual AWS account ID and region.
   - Add your specific KMS key IDs to the `MULTI_REGION_KMS_KEYS` and `SINGLE_REGION_KMS_KEYS` arrays.

3. **Run the Script:**

   ```bash
   chmod +x generate_kms_report.sh
   ./generate_kms_report.sh
   ```

4. **View the Report:**

   After running the script, a CSV file named `kms_key_permissions_report_YYYYMMDD_HHMMSS.csv` will be generated in the current directory. The file contains the following columns:

   - **Role**: The IAM role name.
   - **Policy**: The policy name associated with the role.
   - **Policy Type**: Indicates whether the policy is Inline or Attached.
   - **KMS Key ARN**: The Amazon Resource Name (ARN) of the KMS key.
   - **Permissions/Actions**: The specific actions the policy allows on the KMS key.

## Contributing

If you would like to contribute to this project, please fork the repository and submit a pull request with your proposed changes.

### Instructions:
- Replace placeholders such as `yourusername`, `your-repo-name`, and `your.email@example.com` with your actual GitHub username, repository name, and contact email.
- Ensure that the `LICENSE` file is added if you're including a license.