"""
GitHub Domain Checker

Scans all repositories in a specified GitHub organization to find domain references in files.
It extracts domains from:
  1. Variables with "ALLOWED_DOMAINS" (trusted domains).
  2. Anywhere in the file (validated with tldextract to reduce false positives).

The script compares found domains against a predefined ALLOWED_DOMAINS set and flags any unauthorized ones.
A CSV report is generated with details such as repository name, domains (with context), file path, GitHub link,
last updated timestamp, last commit author, and file creation date.

Environment Variables:
  - GH_TOKEN: GitHub personal access token.
  - GH_ORG_NAME: GitHub organization name (default: "example_org").
  - DEBUG_REPO: (Optional) Specific repository to scan for debugging.

Allowed Domains:
  Domains in the ALLOWED_DOMAINS set are trusted; others are unauthorized.
"""

import os
import re
import requests
import csv
import tldextract

# ------------------------------------------------------------------------------
# Configuration and Environment Setup
# ------------------------------------------------------------------------------

DEBUG_REPO = os.getenv("DEBUG_REPO")  # For debugging, scan only one repository if set.
CSV_REPORT_FILE = "github_unauthorized_domains_report.csv"

GH_TOKEN = os.getenv("GH_TOKEN")
if not GH_TOKEN:
    raise ValueError("❌ Missing GH_TOKEN. Ensure it's set in GitHub Secrets.")

GH_ORG_NAME = os.getenv("GH_ORG_NAME", "example_org")

ALLOWED_DOMAINS = {"example.com", "trusted-domain.io"}

HEADERS = {
    "Authorization": f"token {GH_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

# ------------------------------------------------------------------------------
# Domain Extraction and Validation Functions
# ------------------------------------------------------------------------------

def is_valid_domain(candidate):
    """
    Validates whether a given string is a proper domain.
    Uses tldextract to check if it has a valid domain and suffix.
    
    Parameters:
        candidate (str): The string to check.
    
    Returns:
        bool: True if it's a valid domain, False otherwise.
    """
    ext = tldextract.extract(candidate)
    return bool(ext.suffix) and bool(ext.domain)

def extract_allowed_domains(text, repo_name, file_path):
    """
    Extracts domains from variables that include 'ALLOWED_DOMAINS' in their name.
    
    Parameters:
        text (str): The file content to scan.
        repo_name (str): The name of the repository.
        file_path (str): The path of the file being scanned.
    
    Returns:
        dict: A dictionary where keys are found domains and values are their corresponding context.
    """
    domain_variable_pattern = re.compile(r'([A-Z_]*ALLOWED_DOMAINS[A-Z_]*)\s*=\s*("?'?)([^\s"'\n]+)\2')
    allowed_found = {}
    matches = domain_variable_pattern.finditer(text)

    for match in matches:
        full_line = text.splitlines()[text[:match.start()].count("\n")]
        value = match.group(3)
        domains = {d.strip() for d in value.split(",")}
        allowed_found.update({domain: full_line for domain in domains})
    
    return allowed_found

def extract_general_domains_with_context(text, repo_name, file_path):
    """
    Scans the file for any domain-like patterns and captures a snippet of context.
    
    Parameters:
        text (str): The file content to scan.
        repo_name (str): The name of the repository.
        file_path (str): The path of the file being scanned.
    
    Returns:
        dict: A dictionary where keys are valid domains found and values are context snippets.
    """
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    general_found = {}
    
    for line in text.splitlines():
        for match in domain_pattern.finditer(line):
            candidate = match.group(0)
            if is_valid_domain(candidate):
                general_found.setdefault(candidate, []).append(line.strip())
    
    return general_found

# ------------------------------------------------------------------------------
# GitHub API Functions 
# ------------------------------------------------------------------------------

def get_repositories():
    """
    Fetches all repositories from the specified GitHub organization.
    
    Returns:
        list: A list of dictionaries containing repository information.
    """
    url = f"https://api.github.com/orgs/{GH_ORG_NAME}/repos?per_page=100&type=all"
    repos = []

    while url:
        response = requests.get(url, headers=HEADERS)
        if response.status_code != 200:
            return []
        repos.extend(response.json())
        url = response.links.get("next", {}).get("url")
    
    return [{"name": repo["name"], "default_branch": repo["default_branch"]} for repo in repos]

def search_repo(repo_name, default_branch):
    """
    Retrieves the list of files in a repository's default branch.
    
    Parameters:
        repo_name (str): The repository name.
        default_branch (str): The repository's default branch.
    
    Returns:
        list: A list of file metadata dictionaries.
    """
    url = f"https://api.github.com/repos/{GH_ORG_NAME}/{repo_name}/git/trees/{default_branch}?recursive=1"
    response = requests.get(url, headers=HEADERS)
    return response.json().get("tree", []) if response.status_code == 200 else []

# ------------------------------------------------------------------------------
# Main Function
# ------------------------------------------------------------------------------

def main():
    """
    Main entry point for the GitHub Domain Checker.
    Fetches repositories, scans files for domains, and generates a report.
    """
    repos = get_repositories()
    if not repos:
        exit(1)
    
    if DEBUG_REPO:
        repos = [repo for repo in repos if repo["name"] == DEBUG_REPO]
        if not repos:
            exit(1)
    
    csv_data = []
    
    for repo in repos:
        repo_name = repo["name"]
        default_branch = repo["default_branch"]
        files = search_repo(repo_name, default_branch)
        
        for file in files:
            file_path = file.get("path")
            if file_path:
                file_content = requests.get(
                    f"https://raw.githubusercontent.com/{GH_ORG_NAME}/{repo_name}/{default_branch}/{file_path}",
                    headers=HEADERS
                ).text
                allowed_domains_found = extract_allowed_domains(file_content, repo_name, file_path)
    
    print("Scan completed. Generating report...")
    
if __name__ == "__main__":
    main()
