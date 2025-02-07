#!/usr/bin/env python3
"""
AWS Security Group Report Generator Across All Regions with CIDR Evaluation

This script retrieves all AWS security groups from every available region and generates
a CSV report that includes detailed information about each security group and its inbound/outbound rules.
For each inbound rule, it:
  - Lists the direct IP ranges and any Managed Prefix List entries.
  - Evaluates each CIDR block using the ipaddress module to determine if it is private.
    Any CIDR not in a private network (or 0.0.0.0/0 and ::/0) is considered as allowing
    inbound Internet access.
  - Adds a new column ("CIDR Evaluation") to the CSV output with the evaluation results.
  
For Managed Prefix Lists, the script first attempts to use boto3's API, and if that is not available,
it falls back to using the AWS CLI.

The output CSV file is named with the AWS account number and a timestamp.

Usage:
    python sg_report.py

Dependencies:
    - boto3 (install via pip install boto3)
    - AWS CLI installed and configured
"""

import boto3
import csv
import datetime
import sys
import subprocess
import json
import ipaddress

def get_all_regions():
    """Retrieve all available AWS regions."""
    try:
        ec2 = boto3.client('ec2')
        regions_info = ec2.describe_regions()['Regions']
        regions = [region['RegionName'] for region in regions_info]
        return regions
    except Exception as e:
        sys.stderr.write(f"Error fetching regions: {e}\n")
        sys.exit(1)

def fetch_security_groups(region):
    """Fetch security groups from a specified region."""
    try:
        ec2 = boto3.client('ec2', region_name=region)
        response = ec2.describe_security_groups()
        return response.get('SecurityGroups', [])
    except Exception as e:
        sys.stderr.write(f"Error fetching security groups in region {region}: {e}\n")
        return []

def get_prefix_list_entries(prefix_list_id, region, cache):
    """
    Retrieve the entries of a Managed Prefix List.
    
    First, try to use boto3's API. If that fails, fall back to the AWS CLI.
    
    :param prefix_list_id: The prefix list ID (e.g., 'pl-060fecdad9eeb27b3')
    :param region: The AWS region.
    :param cache: A dict for caching results.
    :return: List of strings for each entry.
    """
    if prefix_list_id in cache:
        return cache[prefix_list_id]

    entries = []
    ec2 = boto3.client('ec2', region_name=region)
    next_token = None

    try:
        # Attempt to use boto3 if available
        if hasattr(ec2, 'describe_managed_prefix_list_entries'):
            while True:
                kwargs = {'PrefixListId': prefix_list_id}
                if next_token:
                    kwargs['NextToken'] = next_token
                response = ec2.describe_managed_prefix_list_entries(**kwargs)
                for entry in response.get('Entries', []):
                    cidr = entry.get('Cidr', '')
                    desc = entry.get('Description', '')
                    entries.append(f"{cidr} ({desc})" if desc else cidr)
                next_token = response.get('NextToken')
                if not next_token:
                    break
        else:
            raise AttributeError("describe_managed_prefix_list_entries is not available")
    except Exception as e:
        sys.stderr.write(
            f"API via boto3 not available ({e}). Falling back to AWS CLI for prefix list {prefix_list_id} in region {region}.\n"
        )
        try:
            # Use the AWS CLI (using the correct command "get-managed-prefix-list-entries")
            cmd = [
                "aws", "ec2", "get-managed-prefix-list-entries",
                "--prefix-list-id", prefix_list_id,
                "--region", region,
                "--output", "json"
            ]
            output = subprocess.check_output(cmd)
            data = json.loads(output)
            for entry in data.get('Entries', []):
                cidr = entry.get('Cidr', '')
                desc = entry.get('Description', '')
                entries.append(f"{cidr} ({desc})" if desc else cidr)
        except Exception as cli_error:
            sys.stderr.write(
                f"Error fetching prefix list entries using CLI for {prefix_list_id} in region {region}: {cli_error}\n"
            )
            entries = []

    cache[prefix_list_id] = entries
    return entries

def process_security_groups(security_groups, region, account_id, writer, prefix_list_cache):
    """
    Process security groups and write each rule to the CSV file.
    
    For inbound rules, also evaluates the CIDRs.
    """
    for sg in security_groups:
        group_id   = sg.get('GroupId', '')
        group_name = sg.get('GroupName', '')
        group_desc = sg.get('Description', '')
        vpc_id     = sg.get('VpcId', '')

        # Process Inbound Rules
        for rule in sg.get('IpPermissions', []):
            protocol  = rule.get('IpProtocol', '')
            from_port = rule.get('FromPort', '')
            to_port   = rule.get('ToPort', '')

            # Build the combined "IP Ranges" field (direct IP ranges and prefix list details)
            ip_ranges = []
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                desc = ip_range.get('Description', '')
                ip_ranges.append(f"{cidr} ({desc})" if desc else cidr)

            prefix_lists = []
            for prefix in rule.get('PrefixListIds', []):
                prefix_list_id = prefix.get('PrefixListId', '')
                entries = get_prefix_list_entries(prefix_list_id, region, prefix_list_cache)
                if entries:
                    prefix_lists.append(f"{prefix_list_id}:\n" + "\n".join(entries))
                else:
                    prefix_lists.append(prefix_list_id)

            # Use newline to join entries instead of a semicolon-space
            combined_sources = "\n".join(ip_ranges + prefix_lists)

            # Evaluate direct IP ranges for inbound rules
            cidr_eval_results = []
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                try:
                    if cidr in ("0.0.0.0/0", "::/0"):
                        cidr_eval_results.append(f"{cidr}: Internet Accessible")
                    else:
                        net = ipaddress.ip_network(cidr, strict=False)
                        if net.is_private:
                            cidr_eval_results.append(f"{cidr}: Private")
                        else:
                            cidr_eval_results.append(f"{cidr}: Internet Accessible")
                except Exception:
                    cidr_eval_results.append(f"{cidr}: Error")
                    
            # Evaluate CIDRs from prefix list entries (if any)
            for prefix in rule.get('PrefixListIds', []):
                prefix_list_id = prefix.get('PrefixListId', '')
                entries = get_prefix_list_entries(prefix_list_id, region, prefix_list_cache)
                for entry in entries:
                    token = entry.split()[0]
                    try:
                        if token in ("0.0.0.0/0", "::/0"):
                            cidr_eval_results.append(f"{token}: Internet Accessible")
                        else:
                            net = ipaddress.ip_network(token, strict=False)
                            if net.is_private:
                                cidr_eval_results.append(f"{token}: Private")
                            else:
                                cidr_eval_results.append(f"{token}: Internet Accessible")
                    except Exception:
                        cidr_eval_results.append(f"{token}: Error")
            # Use newline to separate each CIDR evaluation
            cidr_evaluation = "\n".join(cidr_eval_results)

            writer.writerow({
                'Account ID': account_id,
                'Region': region,
                'Group ID': group_id,
                'Group Name': group_name,
                'Group Description': group_desc,
                'VPC ID': vpc_id,
                'Rule Type': 'Inbound',
                'Protocol': protocol,
                'From Port': from_port,
                'To Port': to_port,
                'IP Ranges': combined_sources,
                'Referenced Groups': "\n".join(
                    f"{pair.get('GroupId', '')} ({pair.get('GroupName', '')}: {pair.get('Description', '')})"
                    for pair in rule.get('UserIdGroupPairs', [])
                ),
                'CIDR Evaluation': cidr_evaluation
            })

        # Process Outbound Rules (CIDR Evaluation left as N/A)
        for rule in sg.get('IpPermissionsEgress', []):
            protocol  = rule.get('IpProtocol', '')
            from_port = rule.get('FromPort', '')
            to_port   = rule.get('ToPort', '')

            ip_ranges = []
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                desc = ip_range.get('Description', '')
                ip_ranges.append(f"{cidr} ({desc})" if desc else cidr)

            prefix_lists = []
            for prefix in rule.get('PrefixListIds', []):
                prefix_list_id = prefix.get('PrefixListId', '')
                entries = get_prefix_list_entries(prefix_list_id, region, prefix_list_cache)
                if entries:
                    prefix_lists.append(f"{prefix_list_id}:\n" + "\n".join(entries))
                else:
                    prefix_lists.append(prefix_list_id)

            combined_sources = "\n".join(ip_ranges + prefix_lists)

            writer.writerow({
                'Account ID': account_id,
                'Region': region,
                'Group ID': group_id,
                'Group Name': group_name,
                'Group Description': group_desc,
                'VPC ID': vpc_id,
                'Rule Type': 'Outbound',
                'Protocol': protocol,
                'From Port': from_port,
                'To Port': to_port,
                'IP Ranges': combined_sources,
                'Referenced Groups': "\n".join(
                    f"{pair.get('GroupId', '')} ({pair.get('GroupName', '')}: {pair.get('Description', '')})"
                    for pair in rule.get('UserIdGroupPairs', [])
                ),
                'CIDR Evaluation': 'N/A'
            })

def main():
    # Get AWS account number using STS
    try:
        sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity().get('Account', 'unknown')
    except Exception as e:
        sys.stderr.write(f"Error fetching AWS account ID: {e}\n")
        sys.exit(1)

    # Create output file name with account number and timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    output_file = f"security_group_report_{account_id}_{timestamp}.csv"

    # Define CSV header fields
    fieldnames = [
        'Account ID',
        'Region',
        'Group ID',
        'Group Name',
        'Group Description',
        'VPC ID',
        'Rule Type',
        'Protocol',
        'From Port',
        'To Port',
        'IP Ranges',
        'Referenced Groups',
        'CIDR Evaluation'
    ]

    regions = get_all_regions()
    print(f"Found regions: {', '.join(regions)}")

    prefix_list_cache = {}
    try:
        with open(output_file, mode='w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for region in regions:
                print(f"Scanning region: {region}")
                sgs = fetch_security_groups(region)
                if sgs:
                    process_security_groups(sgs, region, account_id, writer, prefix_list_cache)
                else:
                    print(f"No security groups found or error in region: {region}")
    except IOError as e:
        sys.stderr.write(f"Error writing to file {output_file}: {e}\n")
        sys.exit(1)

    print(f"Security group report generated successfully: {output_file}")

if __name__ == '__main__':
    main()
