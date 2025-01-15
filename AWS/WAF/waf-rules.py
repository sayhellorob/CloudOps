"""
AWS WAF ACL Rules Script

This script lists the rules enabled in AWS WAF ACLs for a specified scope (REGIONAL or CLOUDFRONT)
and generates a JSON file with the details.

## Prerequisites:
1. Ensure Python 3.x is installed.
2. Configure your AWS credentials using the AWS CLI or environment variables.
   - Run `aws configure` to set up credentials.
3. Install the `boto3` library if not already installed:
   - `pip install boto3`

## Usage:
1. To specify a region and scope via command-line arguments:
   - `python script.py --region us-east-1 --scope REGIONAL`
   - `python script.py --scope CLOUDFRONT`
2. If no region is specified for `REGIONAL`, you will be prompted to select one.
3. The script will generate a JSON file named `waf_acls_<scope>_<region>.json` with the WAF ACL details.

"""

import boto3
import json
import argparse

def list_waf_acls_and_rules(scope, region):
    # Initialize the AWS WAF client
    client = boto3.client('wafv2', region_name=region)
    output_data = {"Scope": scope, "Region": region, "WebACLs": []}

    try:
        # List all WAF Web ACLs
        response = client.list_web_acls(Scope=scope)
        web_acls = response.get('WebACLs', [])

        if not web_acls:
            print(f"No Web ACLs found for scope {scope} in region {region}.")
            return

        for acl in web_acls:
            acl_name = acl['Name']
            acl_id = acl['Id']
            print(f"\nWeb ACL: {acl_name} (ID: {acl_id})")

            # Get details of the Web ACL
            acl_details = client.get_web_acl(
                Name=acl_name,
                Scope=scope,
                Id=acl_id
            )
            acl_rules = acl_details.get('WebACL', {}).get('Rules', [])

            acl_data = {
                "Name": acl_name,
                "Id": acl_id,
                "Rules": []
            }

            if not acl_rules:
                print("  No rules enabled in this Web ACL.")
            else:
                for rule in acl_rules:
                    rule_name = rule.get('Name', 'Unnamed Rule')
                    rule_priority = rule.get('Priority', 'Unknown Priority')
                    rule_action = rule.get('Action', {}).get('Type', 'No Action Defined')
                    print(f"  Rule: {rule_name}")
                    print(f"    Priority: {rule_priority}")
                    print(f"    Action: {rule_action}")
                    
                    # Additional details such as rule conditions
                    statements = rule.get('Statement', {})
                    acl_data["Rules"].append({
                        "Name": rule_name,
                        "Priority": rule_priority,
                        "Action": rule_action,
                        "Statement": statements
                    })

            output_data["WebACLs"].append(acl_data)

        # Write the output data to a JSON file
        output_file = f"waf_acls_{scope}_{region}.json"
        with open(output_file, "w") as json_file:
            json.dump(output_data, json_file, indent=4)
        print(f"\nDetails saved to {output_file}")

    except Exception as e:
        print(f"Error fetching WAF ACLs and rules: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="List WAF ACLs and rules for a specified AWS scope and region.")
    parser.add_argument(
        "-r", "--region",
        help="Specify the AWS region (e.g., us-east-1, us-west-2). Required for REGIONAL scope.",
        default=None
    )
    parser.add_argument(
        "-s", "--scope",
        help="Specify the WAF scope: REGIONAL or CLOUDFRONT.",
        choices=["REGIONAL", "CLOUDFRONT"],
        required=True
    )
    args = parser.parse_args()

    scope = args.scope
    region = args.region

    if scope == "REGIONAL" and not region:
        print("No region specified. Please choose a region:")
        regions = [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-west-3", "ap-southeast-1",
            "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
            "sa-east-1", "ca-central-1", "ap-south-1"
        ]
        for i, reg in enumerate(regions, 1):
            print(f"{i}. {reg}")
        try:
            choice = int(input("Enter the number of the region: "))
            if 1 <= choice <= len(regions):
                region = regions[choice - 1]
            else:
                raise ValueError("Invalid choice")
        except ValueError:
            print("Invalid input. Exiting.")
            exit(1)
    elif scope == "CLOUDFRONT":
        region = "us-east-1"  # CloudFront WAF is global and uses us-east-1

    print(f"Using scope: {scope}, region: {region}")
    list_waf_acls_and_rules(scope, region)
