#!/bin/bash

# Challenge-Response Authentication Test Script

# Configuration
BASE_URL="${BASE_URL:-http://localhost:3000}"
API_BASE="${BASE_URL}/api/auth"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Function to perform login
do_login() {
    local username=$1
    local passcode=$2
    local challenge_id=$3
    local challenge_answer=$4
    
    local data="{\"username\": \"$username\", \"passcode\": \"$passcode\""
    
    if [ ! -z "$challenge_id" ] && [ ! -z "$challenge_answer" ]; then
        data="${data}, \"challengeId\": \"$challenge_id\", \"challengeAnswer\": \"$challenge_answer\""
    fi
    
    data="${data}}"
    
    curl -s -X POST "${API_BASE}/login" \
        -H "Content-Type: application/json" \
        -d "$data"
}

# Function to trigger challenge requirement (3 failed attempts)
trigger_challenge() {
    local username=$1
    
    print_header "Triggering Challenge Requirement"
    print_info "Making 3 failed login attempts for user: $username"
    
    for i in {1..3}; do
        echo -e "\nAttempt $i:"
        response=$(do_login "$username" "wrongpassword")
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    done
    
    print_success "Challenge requirement should now be triggered"
}

# Function to check if challenge is required
check_challenge_required() {
    local username=$1
    
    print_header "Checking Challenge Requirement"
    
    response=$(curl -s -X GET "${API_BASE}/challenge/check?username=$username")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
    
    # Return 0 if challenge is required, 1 otherwise
    echo "$response" | jq -e '.challengeRequired' >/dev/null 2>&1
}

# Function to create a challenge
create_challenge() {
    local username=$1
    
    print_header "Creating Challenge"
    
    response=$(curl -s -X POST "${API_BASE}/challenge/create" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"$username\"}")
    
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
    
    # Extract challenge ID
    challenge_id=$(echo "$response" | jq -r '.challengeId' 2>/dev/null)
    echo "$challenge_id"
}

# Function to verify challenge answer
verify_challenge() {
    local challenge_id=$1
    local answer=$2
    
    print_header "Verifying Challenge Answer"
    
    response=$(curl -s -X POST "${API_BASE}/challenge/verify" \
        -H "Content-Type: application/json" \
        -d "{\"challengeId\": \"$challenge_id\", \"answer\": \"$answer\"}")
    
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
    
    # Return 0 if verification successful, 1 otherwise
    echo "$response" | jq -e '.success' >/dev/null 2>&1
}

# Function to get challenge statistics (admin only)
get_challenge_stats() {
    local admin_token=$1
    
    print_header "Getting Challenge Statistics"
    
    response=$(curl -s -X GET "${API_BASE}/challenge-stats" \
        -H "Authorization: Bearer $admin_token")
    
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

# Main test flow
main() {
    local username="${1:-testuser}"
    local correct_password="${2:-correctpassword}"
    
    print_header "Challenge-Response Authentication Test"
    print_info "Testing with user: $username"
    
    # Step 1: Trigger challenge requirement
    trigger_challenge "$username"
    
    # Step 2: Check if challenge is required
    if check_challenge_required "$username"; then
        print_success "Challenge is required as expected"
    else
        print_error "Challenge is not required (unexpected)"
    fi
    
    # Step 3: Create a challenge
    challenge_id=$(create_challenge "$username")
    if [ ! -z "$challenge_id" ] && [ "$challenge_id" != "null" ]; then
        print_success "Challenge created with ID: $challenge_id"
    else
        print_error "Failed to create challenge"
        exit 1
    fi
    
    # Step 4: Prompt for challenge answer
    print_info "Please check the challenge question above and enter your answer:"
    read -p "Challenge answer: " challenge_answer
    
    # Step 5: Verify the challenge answer
    if verify_challenge "$challenge_id" "$challenge_answer"; then
        print_success "Challenge answer verified successfully"
    else
        print_error "Challenge answer verification failed"
        echo "Continuing anyway to show the failure..."
    fi
    
    # Step 6: Try login with challenge
    print_header "Attempting Login with Challenge"
    response=$(do_login "$username" "$correct_password" "$challenge_id" "$challenge_answer")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
    
    # Check if login was successful
    if echo "$response" | jq -e '.token' >/dev/null 2>&1; then
        print_success "Login successful!"
        token=$(echo "$response" | jq -r '.token')
        print_info "Token: ${token:0:20}..."
    else
        print_error "Login failed"
    fi
    
    # Optional: Get admin stats
    echo -e "\n"
    read -p "Do you want to view challenge statistics? (requires admin login) [y/N]: " view_stats
    
    if [[ $view_stats =~ ^[Yy]$ ]]; then
        print_header "Admin Login"
        admin_response=$(do_login "admin" "adminpassword")
        
        if echo "$admin_response" | jq -e '.token' >/dev/null 2>&1; then
            admin_token=$(echo "$admin_response" | jq -r '.token')
            print_success "Admin login successful"
            get_challenge_stats "$admin_token"
        else
            print_error "Admin login failed"
        fi
    fi
}

# Alternative test: Show challenge requirement in login response
test_login_without_preverify() {
    local username="${1:-testuser}"
    local correct_password="${2:-correctpassword}"
    
    print_header "Alternative Test: Login Without Pre-Verification"
    print_info "This will show challenge requirements in the login response"
    
    # First trigger challenge requirement
    trigger_challenge "$username"
    
    # Now try to login without challenge info
    print_header "Login Attempt Without Challenge Info"
    response=$(do_login "$username" "$correct_password")
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
    
    if echo "$response" | jq -e '.challengeRequired' >/dev/null 2>&1; then
        print_info "Challenge is required. Response contains challenge details."
    fi
}

# Handle command line arguments
case "${1:-}" in
    "test-alt")
        test_login_without_preverify "${2:-testuser}" "${3:-correctpassword}"
        ;;
    "stats")
        print_header "Getting Challenge Statistics Only"
        read -p "Admin password: " -s admin_pass
        echo
        admin_response=$(do_login "admin" "$admin_pass")
        if echo "$admin_response" | jq -e '.token' >/dev/null 2>&1; then
            admin_token=$(echo "$admin_response" | jq -r '.token')
            get_challenge_stats "$admin_token"
        else
            print_error "Admin login failed"
        fi
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [command] [username] [password]"
        echo
        echo "Commands:"
        echo "  (default)    Run the full challenge-response test flow"
        echo "  test-alt     Test login without pre-verification"
        echo "  stats        Get challenge statistics (admin only)"
        echo "  help         Show this help message"
        echo
        echo "Examples:"
        echo "  $0                     # Run with default user 'testuser'"
        echo "  $0 test-alt john pass  # Test alternative flow with user 'john'"
        echo "  $0 stats               # View challenge statistics"
        ;;
    *)
        main "${1:-testuser}" "${2:-correctpassword}"
        ;;
esac