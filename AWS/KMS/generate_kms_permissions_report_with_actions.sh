#!/bin/bash

# Account ID and region where the KMS keys reside
ACCOUNT_ID="YOUR_ACCOUNT_ID"
REGION="YOUR_REGION"

# Generate a timestamp for the report filename
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# CSV output file with timestamp suffix
OUTPUT_FILE="kms_key_permissions_report_${TIMESTAMP}.csv"

# Initialize CSV file with headers
echo "Role,Policy,Policy Type,KMS Key ARN,Permissions/Actions" > $OUTPUT_FILE

# List of Multi-Region KMS key IDs (these keys have the "mrk-" prefix)
MULTI_REGION_KMS_KEYS=(
    "mrk-KEY_ID_1"
    "mrk-KEY_ID_2"
    "mrk-KEY_ID_3"
    # Add more keys as needed
)

# List of Single-Region KMS key IDs (these keys do not have the "mrk-" prefix)
SINGLE_REGION_KMS_KEYS=(
    "KEY_ID_1"
    "KEY_ID_2"
    "KEY_ID_3"
    # Add more keys as needed
)

# Construct full ARNs from the Multi-Region key IDs
MULTI_REGION_KMS_KEY_ARNS=()
for key in "${MULTI_REGION_KMS_KEYS[@]}"; do
    MULTI_REGION_KMS_KEY_ARNS+=("arn:aws:kms:$REGION:$ACCOUNT_ID:key/$key")
done

# Construct full ARNs from the Single-Region key IDs
SINGLE_REGION_KMS_KEY_ARNS=()
for key in "${SINGLE_REGION_KMS_KEYS[@]}"; do
    SINGLE_REGION_KMS_KEY_ARNS+=("arn:aws:kms:$REGION:$ACCOUNT_ID:key/$key")
done

# Combine all KMS ARNs
ALL_KMS_KEY_ARNS=("${MULTI_REGION_KMS_KEY_ARNS[@]}" "${SINGLE_REGION_KMS_KEY_ARNS[@]}")

# Get a list of all IAM roles in the account
ROLES=$(aws iam list-roles --query 'Roles[*].RoleName' --output text)

# Loop through each role and check its policies
for role in $ROLES; do
    echo "Checking role: $role"
    # List all inline and attached policies for the role
    POLICIES=$(aws iam list-role-policies --role-name $role --query 'PolicyNames[*]' --output text)
    ATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name $role --query 'AttachedPolicies[*].PolicyName' --output text)
    
    # Check inline policies
    for policy in $POLICIES; do
        echo "  Checking inline policy: $policy"
        POLICY_DOC=$(aws iam get-role-policy --role-name $role --policy-name $policy --query 'PolicyDocument' --output json)
        for arn in "${ALL_KMS_KEY_ARNS[@]}"; do
            if echo $POLICY_DOC | grep -q "$arn"; then
                ACTIONS=$(echo $POLICY_DOC | jq -r --arg key "$arn" '.Statement[] | select(.Resource == $key) | .Action | if type=="array" then join(", ") else . end')
                echo "    Found KMS key $arn in inline policy $policy of role $role with actions: $ACTIONS"
                echo "$role,$policy,Inline,$arn,\"$ACTIONS\"" >> $OUTPUT_FILE
            fi
        done
    done
    
    # Check attached policies
    for policy in $ATTACHED_POLICIES; do
        echo "  Checking attached policy: $policy"
        POLICY_ARN=$(aws iam list-attached-role-policies --role-name $role --query "AttachedPolicies[?PolicyName=='$policy'].PolicyArn" --output text)
        POLICY_DOC=$(aws iam get-policy-version --policy-arn $POLICY_ARN --version-id $(aws iam get-policy --policy-arn $POLICY_ARN --query 'Policy.DefaultVersionId' --output text) --query 'PolicyVersion.Document' --output json)
        for arn in "${ALL_KMS_KEY_ARNS[@]}"; do
            if echo $POLICY_DOC | grep -q "$arn"; then
                ACTIONS=$(echo $POLICY_DOC | jq -r --arg key "$arn" '.Statement[] | select(.Resource == $key) | .Action | if type=="array" then join(", ") else . end')
                echo "    Found KMS key $arn in attached policy $policy of role $role with actions: $ACTIONS"
                echo "$role,$policy,Attached,$arn,\"$ACTIONS\"" >> $OUTPUT_FILE
            fi
        done
    done
done

echo "Report generated: $OUTPUT_FILE"
