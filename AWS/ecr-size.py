# Run script from AWS CLI --region as needed

# python ecr_storage_calculator.py --region us-east-1


import boto3
import argparse

def calculate_ecr_storage(region):
    client = boto3.client('ecr', region_name=region)
    total_size = 0

    # List all repositories
    repositories = client.describe_repositories()['repositories']
    
    for repo in repositories:
        repo_name = repo['repositoryName']
        print(f"Processing repository: {repo_name}")
        
        # List images in the repository
        images = client.describe_images(repositoryName=repo_name)['imageDetails']
        
        for image in images:
            size = image.get('imageSizeInBytes', 0)  # Get image size
            total_size += size
    
    print(f"Total ECR storage used in region {region}: {total_size / 1024 / 1024:.2f} MB")
    return total_size

if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Calculate total ECR storage usage in a specific region.")
    parser.add_argument('--region', type=str, required=True, help="AWS region to calculate ECR storage usage.")
    args = parser.parse_args()
    
    # Run the storage calculation
    calculate_ecr_storage(args.region)

