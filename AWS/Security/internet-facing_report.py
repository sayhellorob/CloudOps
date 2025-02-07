"""
AWS Internet-Facing Resources Report Script
===========================================

This script scans an AWS account to identify internet-facing resources across 
various AWS services. It collects data on publicly accessible EC2 instances, 
RDS instances, Classic ELBs, ALBs/NLBs, API Gateways, ECS/ECS Fargate services, 
EKS clusters, Internet Gateways, Lambda functions, VPC Peering connections, 
Transit Gateways, CloudFront distributions, and S3 buckets. The identified 
resources and their details are compiled into a CSV report.

The script performs the following tasks:
1. Retrieves a list of all accessible AWS regions.
2. Collects data on publicly accessible resources in each region.
3. Analyzes security group rules to identify open ports.
4. Inspects TLS/SSL configurations for load balancers and CloudFront distributions.
5. Generates a CSV report of all internet-facing resources.

Dependencies:
- boto3
- pandas
- botocore
- json
- ipaddress
- datetime

Usage:
Run the script in an environment with the necessary AWS credentials and permissions.
The generated report will be saved as a CSV file with a timestamped filename.

"""

import boto3
import pandas as pd
import botocore.exceptions
import json
import ipaddress   # For CIDR processing
import datetime    # For timestamping the report

#############################
# Recursive Security Group Analysis Functions
#############################

def get_open_rules_for_sg(sg_id, region, visited=None):
    """
    Recursively retrieves inbound rules for a given security group, including rules
    from any referenced security groups. Returns a list of rule strings that are deemed
    to allow internet access.
    """
    if visited is None:
        visited = set()
    # Avoid infinite loops by not reprocessing the same SG
    if sg_id in visited:
        return []
    visited.add(sg_id)
    
    ec2_client = boto3.client("ec2", region_name=region)
    try:
        response = ec2_client.describe_security_groups(GroupIds=[sg_id])
        sg_info = response["SecurityGroups"][0]
    except Exception as e:
        return [f"Error retrieving sg {sg_id}: {str(e)}"]
    
    rules_list = []
    for rule in sg_info.get("IpPermissions", []):
        # Process direct IP range rules
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if cidr:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if not network.is_private:
                        rule_info = (f"Direct {rule['IpProtocol']}:{rule.get('FromPort', 'All')}-"
                                     f"{rule.get('ToPort', 'All')} (CIDR: {cidr})")
                        rules_list.append(rule_info)
                except Exception:
                    continue
        # Process security group references
        for sg_pair in rule.get("UserIdGroupPairs", []):
            ref_sg = sg_pair.get("GroupId")
            if ref_sg:
                # Record the reference itself
                rule_info = (f"Reference {rule['IpProtocol']}:{rule.get('FromPort', 'All')}-"
                             f"{rule.get('ToPort', 'All')} (ref: {ref_sg})")
                rules_list.append(rule_info)
                # Recursively analyze the referenced security group
                inherited_rules = get_open_rules_for_sg(ref_sg, region, visited)
                for inherited in inherited_rules:
                    # Mark inherited rules so you know they come via the reference
                    rules_list.append(f"Inherited via {ref_sg}: {inherited}")
    return rules_list

def format_rules(rules):
    """
    Takes a list of rule strings and groups them by protocol, returning a
    multi-line formatted string.
    """
    groups = {}
    for rule in rules:
        proto = "OTHER"
        # Attempt to extract protocol info by scanning for tokens containing a colon.
        tokens = rule.split()
        for token in tokens:
            lower_token = token.lower()
            if lower_token.startswith("tcp:"):
                proto = "TCP"
                break
            elif lower_token.startswith("icmp:"):
                proto = "ICMP"
                break
            elif lower_token.startswith("udp:"):
                proto = "UDP"
                break
        groups.setdefault(proto, []).append(rule)
    
    formatted_lines = []
    for proto, rules_list in groups.items():
        formatted_lines.append(f"{proto} Rules:")
        for r in rules_list:
            formatted_lines.append(f"  {r}")
        formatted_lines.append("")  # Blank line after each protocol group
    return "\n".join(formatted_lines)

def get_open_ports_with_sg_recursive(security_group_ids, region):
    """
    For each security group in the provided list, retrieves a recursive list of open inbound rules.
    Returns a tuple of (comma-separated list of SG IDs, formatted multi-line string of detailed rules).
    """
    all_rules = {}
    for sg_id in security_group_ids:
        rules = get_open_rules_for_sg(sg_id, region)
        if rules:
            formatted_rules = format_rules(rules)
            all_rules[sg_id] = formatted_rules
        else:
            all_rules[sg_id] = "None"
    sg_list = ", ".join(all_rules.keys())
    # Separate each security group's block with two newlines.
    ports_list = "\n\n".join([f"{sg}:\n{rules}" for sg, rules in all_rules.items()])
    return sg_list, ports_list

# For backward compatibility, override the earlier get_open_ports_with_sg function.
get_open_ports_with_sg = get_open_ports_with_sg_recursive

#############################
# TLS/SSL Inspection Functions for Load Balancers
#############################

def check_classic_elb_tls_configuration(lb, region):
    """
    Inspects a Classic ELB's listener configuration. Returns a tuple:
    (tls_enabled (bool), details (str)).
    """
    listener_descriptions = lb.get("ListenerDescriptions", [])
    tls_enabled = False
    details = []
    for desc in listener_descriptions:
        listener = desc.get("Listener", {})
        protocol = listener.get("Protocol", "").upper()
        port = listener.get("LoadBalancerPort")
        if protocol == "HTTPS":
            tls_enabled = True
            details.append(f"Port {port}: HTTPS")
        else:
            details.append(f"Port {port}: {protocol}")
    return tls_enabled, "; ".join(details)

def check_alb_tls_configuration(lb_arn, region):
    """
    Inspects an ALB/NLB's listener configuration using the ELBv2 API.
    
    For each listener:
      - If the protocol is HTTPS/TLS, it collects certificate details.
      - If the protocol is HTTP, it checks whether the DefaultActions include
        a redirect action to HTTPS and reports the redirect details.
    
    Returns a tuple: (tls_enabled (bool), details (str)).
    """
    elbv2_client = boto3.client("elbv2", region_name=region)
    try:
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
        tls_enabled = False
        details_list = []
        
        for listener in listeners:
            protocol = listener.get("Protocol", "").upper()
            port = listener.get("Port")
            
            # For HTTPS/TLS listeners, report certificate details.
            if protocol in ["HTTPS", "TLS"]:
                tls_enabled = True
                certs = listener.get("Certificates", [])
                if certs:
                    cert_info = ", ".join([cert.get("CertificateArn", "N/A") for cert in certs])
                else:
                    cert_info = "No certificate details"
                details_list.append(f"Port {port}: {protocol} with certificate(s): {cert_info}")
            
            # For HTTP listeners, check if the default action is a redirect to HTTPS.
            elif protocol == "HTTP":
                default_actions = listener.get("DefaultActions", [])
                redirect_found = False
                for action in default_actions:
                    action_type = action.get("Type")
                    if action_type == "redirect":
                        redirect_found = True
                        redirect_config = action.get("RedirectConfig", {})
                        # Extract redirect details: target protocol, port, and status code.
                        target_protocol = redirect_config.get("Protocol", "not specified")
                        target_port = redirect_config.get("Port", "not specified")
                        status_code = redirect_config.get("StatusCode", "not specified")
                        details_list.append(
                            f"Port {port}: HTTP with default action redirect to {target_protocol} (target port: {target_port}, status: {status_code})"
                        )
                        # Optionally consider a redirect as secure.
                        tls_enabled = True
                if not redirect_found:
                    details_list.append(f"Port {port}: HTTP with no redirect configured")
            
            # For any other protocol.
            else:
                details_list.append(f"Port {port}: {protocol}")
        
        return tls_enabled, "; ".join(details_list)
    except Exception as e:
        print(f"Error retrieving listener configuration for LB {lb_arn}: {e}")
        return False, "Error retrieving TLS configuration"


#############################
# TLS/SSL Inspection Function for CloudFront
#############################

def check_cloudfront_tls_configuration(dist, cloudfront_client):
    """
    Inspects a CloudFront distribution's full configuration (via get_distribution_config)
    to check if TLS/SSL is enforced.
    
    This function retrieves the full distribution config so that certificate details
    (ACMCertificateArn, IAMCertificateId, or Certificate) are available. It then examines:
      - The DefaultCacheBehavior's ViewerProtocolPolicy
      - The ViewerCertificate fields
      
    Returns a tuple: (tls_enabled (bool), details (str)).
    """
    dist_id = dist.get("Id")
    try:
        # Retrieve full distribution configuration
        config_response = cloudfront_client.get_distribution_config(Id=dist_id)
        distribution_config = config_response.get("DistributionConfig", {})
    except Exception as e:
        print(f"Error retrieving distribution config for {dist_id}: {e}")
        distribution_config = dist.get("DistributionConfig", {})

    viewer_certificate = distribution_config.get("ViewerCertificate", {})
    default_cache_behavior = distribution_config.get("DefaultCacheBehavior", {})
    viewer_protocol_policy = default_cache_behavior.get("ViewerProtocolPolicy", "unknown")
    
    tls_enabled = False
    details = []

    # Check the viewer protocol policy: if set to https-only or redirect-to-https, assume TLS is used.
    if viewer_protocol_policy in ["https-only", "redirect-to-https"]:
        tls_enabled = True
    details.append(f"ViewerProtocolPolicy: {viewer_protocol_policy}")

    # Determine which certificate (if any) is in use.
    # If CloudFront is using its default certificate, then no custom certificate is attached.
    if viewer_certificate.get("CloudFrontDefaultCertificate", False):
        details.append("Using CloudFront default certificate")
    else:
        # Check for an ACM certificate
        acm_cert = viewer_certificate.get("ACMCertificateArn")
        # Check for an IAM certificate (used for custom SSL certificates)
        iam_cert = viewer_certificate.get("IAMCertificateId")
        # Some distributions might include a 'Certificate' key
        certificate = viewer_certificate.get("Certificate")
        
        if acm_cert:
            tls_enabled = True
            details.append(f"ACM Certificate: {acm_cert}")
        elif iam_cert:
            tls_enabled = True
            details.append(f"IAM Certificate: {iam_cert}")
        elif certificate:
            tls_enabled = True
            details.append(f"Custom Certificate: {certificate}")
        else:
            details.append("No certificate details found")

    # Optionally, add other fields if available
    cert_source = viewer_certificate.get("CertificateSource")
    if cert_source:
        details.append(f"CertificateSource: {cert_source}")
    min_protocol = viewer_certificate.get("MinimumProtocolVersion")
    if min_protocol:
        details.append(f"MinimumProtocolVersion: {min_protocol}")
    
    return tls_enabled, "; ".join(details)



#############################
# End Recursive Analysis and TLS Inspection Functions
#############################

# Get all AWS regions
def get_accessible_regions():
    ec2 = boto3.client("ec2", region_name="us-east-1")  # Use default region
    all_regions = [region["RegionName"] for region in ec2.describe_regions()["Regions"]]
    accessible_regions = []
    print("🔍 Checking accessible regions...")
    for region in all_regions:
        try:
            test_client = boto3.client("ec2", region_name=region)
            test_client.describe_instances()  # Test call to check access
            accessible_regions.append(region)
        except botocore.exceptions.ClientError as e:
            print(f"🚫 Skipping region {region}: {e.response['Error']['Code']}")
    print(f"✅ Accessible regions: {', '.join(accessible_regions)}")
    return accessible_regions

# Function to get listener ports for ALBs (using ELBv2)
def get_listener_ports(lb_arn, region):
    elbv2_client = boto3.client("elbv2", region_name=region)
    try:
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
        return ", ".join([f"{listener['Protocol']}:{listener['Port']}" for listener in listeners])
    except botocore.exceptions.ClientError:
        return "Error retrieving listeners"

# Collect data from all AWS regions
all_data = []
regions = get_accessible_regions()

for region in regions:
    print(f"🔍 Scanning region: {region}")
    
    # Initialize clients for various services in this region
    ec2_client = boto3.client("ec2", region_name=region)
    elb_client = boto3.client("elb", region_name=region)           # For Classic ELBs
    elbv2_client = boto3.client("elbv2", region_name=region)         # For ALBs / NLBs
    rds_client = boto3.client("rds", region_name=region)
    s3_client = boto3.client("s3", region_name=region)
    apigateway_client = boto3.client("apigateway", region_name=region)
    cloudfront_client = boto3.client("cloudfront", region_name=region)
    eks_client = boto3.client("eks", region_name=region)
    lambda_client = boto3.client("lambda", region_name=region)
    ecs_client = boto3.client("ecs", region_name=region)
    
    # -------------------------
    # Collect EC2 Instances (Public)
    # -------------------------
    instances = ec2_client.describe_instances()
    for reservation in instances.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            if instance.get("PublicIpAddress"):
                security_groups = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
                sg_ids, open_ports = get_open_ports_with_sg(security_groups, region)
                all_data.append({
                    "Component": "EC2",
                    "ID": instance.get("InstanceId"),
                    "Public IP": instance.get("PublicIpAddress"),
                    "Region": region,
                    "Security Groups": sg_ids,
                    "Open Ports": open_ports,
                    "Exposure": "Publicly Accessible",
                })
    
    # -------------------------
    # Collect Public RDS Instances
    # -------------------------
    for rds in rds_client.describe_db_instances().get("DBInstances", []):
        if rds.get("PubliclyAccessible"):
            security_groups = [sg["VpcSecurityGroupId"] for sg in rds.get("VpcSecurityGroups", [])]
            sg_ids, open_ports = get_open_ports_with_sg(security_groups, region)
            all_data.append({
                "Component": "RDS",
                "ID": rds.get("DBInstanceIdentifier"),
                "Public Endpoint": rds.get("Endpoint", {}).get("Address"),
                "Region": region,
                "Security Groups": sg_ids,
                "Open Ports": open_ports,
                "Exposure": "Publicly Accessible",
            })
    
    # -------------------------
    # Collect Public Classic ELBs
    # -------------------------
    for lb in elb_client.describe_load_balancers().get("LoadBalancerDescriptions", []):
        if lb.get("Scheme") == "internet-facing":
            security_groups = lb.get("SecurityGroups", [])
            sg_ids, open_ports = get_open_ports_with_sg(security_groups, region)
            # Check TLS configuration for Classic ELB
            tls_enabled, tls_details = check_classic_elb_tls_configuration(lb, region)
            all_data.append({
                "Component": "Classic ELB",
                "ID": lb.get("LoadBalancerName"),
                "Public DNS": lb.get("DNSName"),
                "Region": region,
                "Security Groups": sg_ids,
                "Open Ports": open_ports,
                "Listener Ports": tls_details,  # Displaying listener details (including TLS info)
                "TLS/SSL": tls_details,
                "Exposure": "Publicly Accessible",
            })
    
    # -------------------------
    # Collect Public ALBs and NLBs (ELBv2)
    # -------------------------
    try:
        alb_response = elbv2_client.describe_load_balancers()
        for lb in alb_response.get("LoadBalancers", []):
            if lb.get("Scheme") == "internet-facing":
                # Determine the type of load balancer (application vs network)
                lb_type = lb.get("Type", "application")
                component = "ALB" if lb_type == "application" else "NLB" if lb_type == "network" else "Load Balancer"
                # For application load balancers, security groups apply; for NLBs they do not.
                security_groups = lb.get("SecurityGroups", []) if lb_type == "application" else []
                sg_ids, open_ports = get_open_ports_with_sg(security_groups, region) if security_groups else ("N/A", "N/A")
                lb_arn = lb.get("LoadBalancerArn")
                listener_ports = get_listener_ports(lb_arn, region) if lb_arn else "Managed by AWS"
                tls_enabled, tls_details = check_alb_tls_configuration(lb_arn, region)
                all_data.append({
                    "Component": component,
                    "ID": lb.get("LoadBalancerName"),
                    "Public DNS": lb.get("DNSName"),
                    "Region": region,
                    "Security Groups": ", ".join(security_groups) if security_groups else "N/A",
                    "Open Ports": open_ports,
                    "Listener Ports": listener_ports,
                    "TLS/SSL": tls_details,
                    "Exposure": "Publicly Accessible",
                })
    except botocore.exceptions.ClientError as e:
        print(f"🚫 Error retrieving ALBs/NLBs in {region}: {e}")
    

    # -------------------------
    # Collect Public API Gateways
    # -------------------------
    for api in apigateway_client.get_rest_apis().get("items", []):
        api_id = api.get("id")
        
        # Retrieve and parse resource policy details
        resource_policy_summary = "None"
        try:
            api_details = apigateway_client.get_rest_api(restApiId=api_id)
            policy_str = api_details.get("policy")
            if policy_str:
                # Optionally, you can parse policy_str for specific details.
                resource_policy_summary = policy_str
            else:
                resource_policy_summary = "None"
        except botocore.exceptions.ClientError as e:
            resource_policy_summary = f"Error retrieving policy: {e.response['Error']['Message']}"
        except Exception as e:
            resource_policy_summary = f"Error retrieving policy: {str(e)}"
        
        # Retrieve API Authorizers and add Lambda function details if applicable
        authorizers_list = "None"
        try:
            authorizers_response = apigateway_client.get_authorizers(restApiId=api_id)
            authorizers = authorizers_response.get("items", [])
            authorizer_details = []
            for auth in authorizers:
                # Start with basic authorizer name and type.
                detail = f"{auth.get('name')} (Type: {auth.get('type')})"
                
                # Check if this authorizer is Lambda-based by examining the authorizerUri.
                auth_uri = auth.get("authorizerUri", "")
                if auth_uri and "lambda" in auth_uri.lower():
                    # The authorizerUri usually looks like:
                    # "arn:aws:apigateway:<region>:lambda:path/2015-03-31/functions/arn:aws:lambda:<region>:<account-id>:function:<function-name>/invocations"
                    if "functions/" in auth_uri:
                        try:
                            lambda_arn_with_invocations = auth_uri.split("functions/")[1]
                            lambda_arn = lambda_arn_with_invocations.split("/invocations")[0]
                            lambda_function_name = lambda_arn.split(":")[-1]
                            detail += f", Lambda Function: {lambda_function_name}"
                            
                            # Optionally, retrieve additional Lambda details.
                            try:
                                lambda_details = lambda_client.get_function(FunctionName=lambda_function_name)
                                configuration = lambda_details.get("Configuration", {})
                                runtime = configuration.get("Runtime", "Unknown")
                                last_modified = configuration.get("LastModified", "Unknown")
                                description = configuration.get("Description", "No description")
                                detail += f" [Runtime: {runtime}, LastModified: {last_modified}, Description: {description}]"
                            except Exception as e:
                                detail += " [Unable to retrieve Lambda details]"
                        except Exception as e:
                            detail += f", Error parsing Lambda function: {str(e)}"
                authorizer_details.append(detail)
            if authorizer_details:
                authorizers_list = ", ".join(authorizer_details)
            else:
                authorizers_list = "None"
        except botocore.exceptions.ClientError as e:
            authorizers_list = f"Error retrieving authorizers: {e.response['Error']['Message']}"
        except Exception as e:
            authorizers_list = f"Error retrieving authorizers: {str(e)}"
        
        all_data.append({
            "Component": "API Gateway",
            "ID": api_id,
            "Region": region,
            "Exposure": "Publicly Accessible",
            "Resource Policy": resource_policy_summary,
            "Authorizers": authorizers_list,
        })


    # -------------------------
    # Collect ECS and ECS Fargate Services
    # -------------------------
    try:
        cluster_arns = ecs_client.list_clusters().get("clusterArns", [])
        for cluster_arn in cluster_arns:
            service_arns = ecs_client.list_services(cluster=cluster_arn).get("serviceArns", [])
            if service_arns:
                service_details = ecs_client.describe_services(cluster=cluster_arn, services=service_arns).get("services", [])
                for service in service_details:
                    service_name = service.get("serviceName")
                    launch_type = service.get("launchType", "N/A")
                    network_config = service.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
                    assign_public_ip = network_config.get("assignPublicIp", "DISABLED")
                    exposure = "Publicly Accessible" if assign_public_ip.upper() == "ENABLED" else "Not Public"
                    all_data.append({
                        "Component": "ECS/ECS Fargate",
                        "ID": service_name,
                        "Cluster": cluster_arn,
                        "Region": region,
                        "Launch Type": launch_type,
                        "Assign Public IP": assign_public_ip,
                        "Exposure": exposure,
                    })
    except botocore.exceptions.ClientError as e:
        print(f"🚫 Error retrieving ECS services in {region}: {e}")
    
    # -------------------------
    # Collect EKS Clusters (with security groups and public access CIDRs)
    # -------------------------
    try:
        eks_clusters = eks_client.list_clusters().get("clusters", [])
        for cluster_name in eks_clusters:
            cluster_info = eks_client.describe_cluster(name=cluster_name).get("cluster", {})
            vpc_config = cluster_info.get("resourcesVpcConfig", {})
            public_access = vpc_config.get("endpointPublicAccess", False)
            exposure = "Publicly Accessible" if public_access else "Not Public"
            # Get the raw list of security groups associated with the cluster
            security_groups = vpc_config.get("securityGroupIds", [])
            all_sgs = ", ".join(security_groups) if security_groups else "None"
            # Recursively analyze the security groups for inbound rules allowing public access
            sg_ids, open_ports = get_open_ports_with_sg(security_groups, region)
            # Capture the public access CIDRs (the API server allowlist)
            public_access_cidrs = vpc_config.get("publicAccessCidrs", [])
            public_access_cidrs_str = ", ".join(public_access_cidrs) if public_access_cidrs else "None"
            all_data.append({
                "Component": "EKS",
                "ID": cluster_info.get("name"),
                "Region": region,
                "Public Endpoint": public_access,
                "All Security Groups": all_sgs,
                "Security Groups (Open Rules)": sg_ids,
                "Open Ports": open_ports,
                "Public Access CIDRs": public_access_cidrs_str,
                "Exposure": exposure,
            })
    except botocore.exceptions.ClientError as e:
        print(f"🚫 Error retrieving EKS clusters in {region}: {e}")
    
    # # -------------------------
    # # Collect Internet Gateways (IGW)
    # # -------------------------
    # try:
    #     igws = ec2_client.describe_internet_gateways().get("InternetGateways", [])
    #     for igw in igws:
    #         attachments = igw.get("Attachments", [])
    #         attached_vpcs = ", ".join([attachment.get("VpcId", "Unknown") for attachment in attachments]) if attachments else "None"
    #         all_data.append({
    #             "Component": "Internet Gateway",
    #             "ID": igw.get("InternetGatewayId"),
    #             "Region": region,
    #             "Attached VPCs": attached_vpcs,
    #             "Exposure": "N/A",  # IGWs themselves are not treated as internet-facing endpoints
    #         })
    # except botocore.exceptions.ClientError as e:
    #     print(f"🚫 Error retrieving Internet Gateways in {region}: {e}")
    
    # -------------------------
    # Collect Publicly Accessible Lambda Functions
    # -------------------------
    try:
        lambda_functions = lambda_client.list_functions().get("Functions", [])
        for function in lambda_functions:
            public_access = "No"
            try:
                policy_response = lambda_client.get_policy(FunctionName=function.get("FunctionName"))
                policy_doc = json.loads(policy_response.get("Policy", "{}"))
                for statement in policy_doc.get("Statement", []):
                    principal = statement.get("Principal")
                    if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                        public_access = "Yes"
                        break
            except lambda_client.exceptions.ResourceNotFoundException:
                public_access = "No"
            exposure = "Publicly Accessible" if public_access == "Yes" else "Not Public"
            all_data.append({
                "Component": "Lambda",
                "ID": function.get("FunctionName"),
                "Region": region,
                "Public Access": public_access,
                "Exposure": exposure,
            })
    except botocore.exceptions.ClientError as e:
        print(f"🚫 Error retrieving Lambda functions in {region}: {e}")
    
    # -------------------------
    # Collect VPC Peering Connections
    # -------------------------
    try:
        vpc_peerings = ec2_client.describe_vpc_peering_connections().get("VpcPeeringConnections", [])
        for peering in vpc_peerings:
            requester = peering.get("RequesterVpcInfo", {}).get("VpcId", "Unknown")
            accepter = peering.get("AccepterVpcInfo", {}).get("VpcId", "Unknown")
            all_data.append({
                "Component": "VPC Peering",
                "ID": peering.get("VpcPeeringConnectionId"),
                "Region": region,
                "Requester VPC": requester,
                "Accepter VPC": accepter,
                "Status": peering.get("Status", {}).get("Code"),
                "Exposure": "N/A",
            })
    except botocore.exceptions.ClientError as e:
        print(f"🚫 Error retrieving VPC Peering Connections in {region}: {e}")
    
    # -------------------------
    # Collect Transit Gateways
    # -------------------------
    try:
        transit_gateways = ec2_client.describe_transit_gateways().get("TransitGateways", [])
        for tg in transit_gateways:
            all_data.append({
                "Component": "Transit Gateway",
                "ID": tg.get("TransitGatewayId"),
                "Region": region,
                "State": tg.get("State"),
                "Exposure": "N/A",
            })
    except botocore.exceptions.ClientError as e:
        print(f"🚫 Error retrieving Transit Gateways in {region}: {e}")

# -------------------------
# Global Resources (not region-specific)
# -------------------------

# CloudFront Distributions
try:
    distributions = cloudfront_client.list_distributions()
    if "DistributionList" in distributions and "Items" in distributions["DistributionList"]:
        for dist in distributions["DistributionList"]["Items"]:
            tls_enabled, tls_details = check_cloudfront_tls_configuration(dist, cloudfront_client)
            exposure = "Publicly Accessible"
            all_data.append({
                "Component": "CloudFront",
                "ID": dist.get("Id"),
                "Public Domain": dist.get("DomainName"),
                "Region": "Global",
                "Exposure": exposure,
                "TLS/SSL": tls_details,
            })
except botocore.exceptions.ClientError as e:
    print(f"🚫 Error retrieving CloudFront distributions: {e}")


# S3 Buckets
try:
    buckets = s3_client.list_buckets().get("Buckets", [])
    for bucket in buckets:
        bucket_name = bucket.get("Name")
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            public_found = False
            for grant in acl.get("Grants", []):
                if "AllUsers" in grant.get("Grantee", {}).get("URI", ""):
                    public_found = True
                    break
            if public_found:
                all_data.append({
                    "Component": "S3",
                    "ID": bucket_name,
                    "Region": "Global",
                    "Public Access": "Yes",
                    "Exposure": "Publicly Accessible",
                })
        except botocore.exceptions.ClientError:
            all_data.append({
                "Component": "S3",
                "ID": bucket_name,
                "Region": "Global",
                "Public Access": "Unknown",
                "Exposure": "Access Denied (Review Required)",
            })
except botocore.exceptions.ClientError as e:
    print(f"🚫 Error retrieving S3 buckets: {e}")

# Convert data to DataFrame and filter for internet-facing components
df = pd.DataFrame(all_data)
df_internet_facing = df[df["Exposure"] == "Publicly Accessible"]

# Retrieve account number and current timestamp for the report file name
sts_client = boto3.client("sts")
account_id = sts_client.get_caller_identity()["Account"]
timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
report_path = f"aws_internet_facing_report_{account_id}_{timestamp}.csv"

# Save the filtered report
df_internet_facing.to_csv(report_path, index=False)

print(f"✅ Internet-facing report generated: {report_path}")
