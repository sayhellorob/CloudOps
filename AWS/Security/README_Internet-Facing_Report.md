# AWS Internet-Facing Report Generator

A Python tool to scan your AWS account for publicly accessible resources. This script recursively analyzes AWS Security Groups and gathers data across multiple AWS services to generate a comprehensive CSV report of internet-facing components.

## Features

- **Recursive Security Group Analysis**:  
  Scans and analyzes inbound rules for security groups—including following references to other security groups—to identify rules that allow internet access.

- **Multi-Region Scanning**:  
  Automatically checks all accessible AWS regions for public-facing resources.

- **Service Coverage**:  
  Collects data from a variety of AWS services including:
  - **EC2 Instances** (with public IP addresses)
  - **RDS Instances** (publicly accessible databases)
  - **Classic ELBs and ALBs** (internet-facing load balancers)
  - **API Gateways**
  - **ECS/ECS Fargate Services**
  - **EKS Clusters**
  - **Lambda Functions** (with public access policies)
  - **Internet Gateways**
  - **VPC Peering Connections**
  - **Transit Gateways**
  - **CloudFront Distributions**
  - **S3 Buckets** (with public ACL settings)

- **CSV Report Generation**:  
  Outputs a timestamped CSV report containing details on all detected internet-facing resources, including associated security group details and open ports.

## Requirements

- **Python 3.x**

- **AWS Credentials**  
  Ensure that your AWS credentials are configured (via environment variables, AWS CLI, or IAM roles) so that the script can authenticate and interact with AWS services.

- **Python Dependencies**  
  Install the required Python libraries using pip:

  ```bash
  pip install boto3 pandas botocore

## How It Works

- **Security Group Analysis**:
  The script includes recursive functions to analyze security group rules. It follows references to other security groups to ensure that inherited permissions are evaluated, grouping open rules by protocol for clarity.

- **Service Scanning**:
  For each AWS region accessible to your account, the script initializes AWS service clients (e.g., EC2, RDS, ELB, ALB, API Gateway, ECS, EKS, Lambda, etc.) and collects data on resources that are publicly accessible.

- **Report Generation**:
  All collected data is compiled into a pandas DataFrame, filtered for "Publicly Accessible" entries, and then saved as a CSV file with your AWS account number and a timestamp.
