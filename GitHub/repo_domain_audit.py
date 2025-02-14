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
    ext = tldextract.extract(candidate)
    return bool(ext.suffix) and bool(ext.domain)

def extract_allowed_domains(text, repo_name, file_path):
    domain_variable_pattern = re.compile(r'([A-Z_]*ALLOWED_DOMAINS[A-Z_]*)\s*=\s*("?\'?)([^\s"'\n]+)\2')
    allowed_found = {}
    matches = domain_variable_pattern.finditer(text)

    for match in matches:
        full_line = text.splitlines()[text[:match.start()].count("\n")]
        value = match.group(3)
        domains = {d.strip() for d in value.split(",")}
        allowed_found.update({domain: full_line for domain in domains})
    
    return allowed_found

def extract_general_domains_with_context(text, repo_name, file_path):
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
    url = f"https://api.github.com/repos/{GH_ORG_NAME}/{repo_name}/git/trees/{default_branch}?recursive=1"
    response = requests.get(url, headers=HEADERS)
    return response.json().get("tree", []) if response.status_code == 200 else []

def get_file_metadata(repo_name, file_path, default_branch):
    url = f"https://api.github.com/repos/{GH_ORG_NAME}/{repo_name}/commits?path={file_path}&sha={default_branch}&per_page=100"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200 and response.json():
        commits = response.json()
        last_commit = commits[0]
        last_updated = last_commit["commit"]["committer"]["date"]
        last_author = last_commit["commit"].get("author", {}).get("name", last_commit["commit"]["committer"]["name"])
        created_date = commits[-1]["commit"]["committer"]["date"] if len(commits) > 1 else last_updated
        return last_updated, last_author, created_date
    return "Unknown", "Unknown", "Unknown"

# ------------------------------------------------------------------------------
# Main Function
# ------------------------------------------------------------------------------

def main():
    repos = get_repositories()
    if not repos:
        exit(1)
    
    if DEBUG_REPO:
        repos = [repo for repo in repos if repo["name"] == DEBUG_REPO]
        if not repos:
            exit(1)
    
    csv_data = []
    csv_headers = [
        "Repository", "VAR Allowed_Domains", "VAR Allowed_Domains Context", 
        "Other Domains Found", "Other Domains Context", "File Path", "GitHub Link", 
        "Last Updated", "Last Updated By", "File Created Date"
    ]
    
    for repo in repos:
        repo_name = repo["name"]
        default_branch = repo["default_branch"]
        files = search_repo(repo_name, default_branch)
        
        for file in files:
            file_path = file.get("path")
            if file_path:
                try:
                    file_content = requests.get(
                        f"https://raw.githubusercontent.com/{GH_ORG_NAME}/{repo_name}/{default_branch}/{file_path}",
                        headers=HEADERS
                    ).text
                    
                    allowed_domains_found = extract_allowed_domains(file_content, repo_name, file_path)
                    general_domains_found = extract_general_domains_with_context(file_content, repo_name, file_path)
                    
                    for domain in allowed_domains_found.keys():
                        general_domains_found.pop(domain, None)
                    
                    if allowed_domains_found or general_domains_found:
                        last_updated, last_author, created_date = get_file_metadata(repo_name, file_path, default_branch)
                    else:
                        last_updated, last_author, created_date = "N/A", "N/A", "N/A"
                    
                    csv_data.append([
                        repo_name, ", ".join(allowed_domains_found.keys()), " || ".join(allowed_domains_found.values()),
                        ", ".join(general_domains_found.keys()), " || ".join(
                            f"{dom}: {' | '.join(ctxs)}" for dom, ctxs in general_domains_found.items()
                        ), file_path, f"https://github.com/{GH_ORG_NAME}/{repo_name}/blob/{default_branch}/{file_path}",
                        last_updated, last_author, created_date
                    ])
                except Exception:
                    pass
    
    with open(CSV_REPORT_FILE, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(csv_headers)
        writer.writerows(csv_data)

if __name__ == "__main__":
    main()
