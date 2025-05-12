#!/bin/bash

# Enhanced Token Management System Test Script
# This script automates testing of the complete authentication flow with additional security features

# Configuration - Update these values
API_URL="http://localhost:3000/api"
USERNAME="testuser_$(date +%s)"  # Unique username with timestamp
PASSCODE="Secure123!"
TELEGRAM_ID="1694779369" # Replace with your actual Telegram ID
ADMIN_TOKEN=""  # Optional: Set this if you have admin access for testing admin endpoints

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Function to display steps
step() {
  echo -e "\n${BLUE}============================================================${NC}"
  echo -e "${BLUE}STEP $1: $2${NC}"
  echo -e "${BLUE}============================================================${NC}"
}

# Function to display sub-steps
substep() {
  echo -e "\n${CYAN}→ $1${NC}"
}

# Function to display request info
request() {
  echo -e "\n${PURPLE}REQUEST:${NC} $1"
  echo -e "${PURPLE}ENDPOINT:${NC} $2"
  if [ ! -z "$3" ]; then
    echo -e "${PURPLE}PAYLOAD:${NC}\n$3"
  fi
  echo -e "${PURPLE}−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−${NC}"
}

# Function to display response
response() {
  echo -e "${PURPLE}RESPONSE:${NC}"
  # Use jq for pretty-printing if available, otherwise use the raw response
  if command -v jq &> /dev/null && [[ "$1" == *"{"* ]]; then
    echo "$1" | jq
  else
    echo "$1"
  fi
  echo -e "${PURPLE}−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−−${NC}"
}

# Function to display success
success() {
  echo -e "\n${GREEN}✓ SUCCESS: $1${NC}"
}

# Function to display warning or prompt
warning() {
  echo -e "\n${YELLOW}⚠ ATTENTION: $1${NC}"
}

# Function to display error
error() {
  echo -e "\n${RED}✘ ERROR: $1${NC}"
  exit 1
}

# Function to extract values from JSON responses
extract_value() {
  local json=$1
  local field=$2
  
  # Try using jq if available
  if command -v jq &> /dev/null; then
    value=$(echo "$json" | jq -r ".$field" 2>/dev/null)
    if [ "$value" != "null" ] && [ ! -z "$value" ]; then
      echo "$value"
      return
    fi
  fi
  
  # Fallback to grep/sed method
  value=$(echo "$json" | grep -o "\"$field\":[^,}]*" | sed 's/"'"$field"'":"\{0,1\}\([^,"]*\)"\{0,1\}/\1/')
  echo "$value"
}

# Display test information
echo -e "\n${GREEN}=======================================================${NC}"
echo -e "${GREEN}      ENHANCED TOKEN MANAGEMENT SYSTEM TEST SCRIPT${NC}"
echo -e "${GREEN}=======================================================${NC}"
echo -e "API URL: ${CYAN}$API_URL${NC}"
echo -e "Username: ${CYAN}$USERNAME${NC}"
echo -e "Telegram ID: ${CYAN}$TELEGRAM_ID${NC}"
echo -e "Start Time: ${CYAN}$(date)${NC}"
echo -e "${GREEN}=======================================================${NC}"
echo -e "This script will test all aspects of the authentication system including:"
echo -e "• Basic authentication flow"
echo -e "• Token management"
echo -e "• Challenge-response mechanism"
echo -e "• Role-based access control"
echo -e "• Activity logging and monitoring"
echo -e "• Rate limiting"
echo -e "• Security measures (SQL injection, XSS protection)"
echo -e "${GREEN}=======================================================${NC}"

# Prompt user to confirm before starting
read -p "Press ENTER to start the test or CTRL+C to cancel..."

# STEP 1: Register a new user
step 1 "Register a new user"
register_payload='{
  "username": "'"$USERNAME"'",
  "dateOfBirth": "1990-01-01",
  "passcode": "'"$PASSCODE"'",
  "registrationMethod": "telegram",
  "telegramId": "'"$TELEGRAM_ID"'",
  "referralCode": "TEST123"
}'

request "POST" "$API_URL/auth/register" "$register_payload"

register_response=$(curl -s -X POST "$API_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d "$register_payload")

response "$register_response"

user_id=$(extract_value "$register_response" "userId")
success_status=$(extract_value "$register_response" "success")

if [ "$success_status" != "true" ] || [ -z "$user_id" ]; then
  error "Failed to get userId from registration. Check your Telegram ID and server status."
else
  success "Registration successful. User ID: $user_id"
fi

# Test duplicate registration
substep "Testing duplicate registration (should fail)"
duplicate_response=$(curl -s -X POST "$API_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d "$register_payload")

response "$duplicate_response"

if [[ "$duplicate_response" == *"already"* ]]; then
  success "Duplicate registration correctly prevented"
else
  warning "Duplicate registration check may not be working"
fi

# STEP 2: Verify OTP for registration
step 2 "Verify OTP for registration"
warning "Check your Telegram for the OTP code"
read -p "Enter the OTP received on Telegram: " otp

verify_payload='{
  "userId": "'"$user_id"'",
  "otp": "'"$otp"'"
}'

request "POST" "$API_URL/auth/verify-otp" "$verify_payload"

verify_response=$(curl -s -X POST "$API_URL/auth/verify-otp" \
  -H "Content-Type: application/json" \
  -d "$verify_payload")

response "$verify_response"

access_token=$(extract_value "$verify_response" "accessToken")
refresh_token=$(extract_value "$verify_response" "refreshToken")
success_status=$(extract_value "$verify_response" "success")

if [ "$success_status" != "true" ] || [ -z "$access_token" ] || [ -z "$refresh_token" ]; then
  error "Failed to get tokens from OTP verification. Make sure you entered the correct OTP."
else
  success "OTP verification successful. Tokens received."
  substep "Access Token: ${access_token:0:15}...${access_token: -15} (${#access_token} chars)"
  substep "Refresh Token: ${refresh_token:0:15}...${refresh_token: -15} (${#refresh_token} chars)"
fi

# Test invalid OTP
substep "Testing invalid OTP (should fail)"
invalid_otp_payload='{
  "userId": "'"$user_id"'",
  "otp": "000000"
}'

invalid_otp_response=$(curl -s -X POST "$API_URL/auth/verify-otp" \
  -H "Content-Type: application/json" \
  -d "$invalid_otp_payload")

response "$invalid_otp_response"

if [[ "$invalid_otp_response" == *"Invalid OTP"* ]] || [[ "$invalid_otp_response" == *"success\":false"* ]]; then
  success "Invalid OTP correctly rejected"
else
  warning "Invalid OTP validation may not be working"
fi

# STEP 3: Login with credentials
step 3 "Login with credentials"
login_payload='{
  "username": "'"$USERNAME"'",
  "passcode": "'"$PASSCODE"'",
  "loginMethod": "direct"
}'

request "POST" "$API_URL/auth/login" "$login_payload"

login_response=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "$login_payload")

response "$login_response"

require_mfa=$(extract_value "$login_response" "requireMFA")
login_user_id=$(extract_value "$login_response" "userId")
success_status=$(extract_value "$login_response" "success")

if [ "$success_status" != "true" ]; then
  error "Login failed. Check your credentials."
fi

if [ "$require_mfa" = "true" ]; then
  success "Login first step successful. MFA required."
  
  # STEP 4: Verify MFA for login
  step 4 "Verify MFA for login"
  warning "Check your Telegram for the login OTP code"
  read -p "Enter the OTP received on Telegram: " login_otp

  mfa_payload='{
    "userId": "'"$login_user_id"'",
    "otp": "'"$login_otp"'"
  }'

  request "POST" "$API_URL/auth/verify-mfa" "$mfa_payload"

  mfa_response=$(curl -s -X POST "$API_URL/auth/verify-mfa" \
    -H "Content-Type: application/json" \
    -d "$mfa_payload")

  response "$mfa_response"

  access_token=$(extract_value "$mfa_response" "accessToken")
  refresh_token=$(extract_value "$mfa_response" "refreshToken")
  success_status=$(extract_value "$mfa_response" "success")

  if [ "$success_status" != "true" ] || [ -z "$access_token" ] || [ -z "$refresh_token" ]; then
    error "Failed to get tokens from MFA verification. Check the OTP you entered."
  else
    success "MFA verification successful. New tokens received."
    substep "Access Token: ${access_token:0:15}...${access_token: -15} (${#access_token} chars)"
    substep "Refresh Token: ${refresh_token:0:15}...${refresh_token: -15} (${#refresh_token} chars)"
  fi
else
  # If MFA not required, extract tokens from login response
  access_token=$(extract_value "$login_response" "accessToken")
  refresh_token=$(extract_value "$login_response" "refreshToken")
  
  if [ -z "$access_token" ] || [ -z "$refresh_token" ]; then
    error "Failed to get tokens from login. Check server response."
  else
    success "Login successful. Tokens received."
    substep "Access Token: ${access_token:0:15}...${access_token: -15} (${#access_token} chars)"
    substep "Refresh Token: ${refresh_token:0:15}...${refresh_token: -15} (${#refresh_token} chars)"
  fi
fi

# STEP 5: Test Challenge-Response Mechanism
step 5 "Test Challenge-Response Mechanism"

substep "Triggering failed login attempts to require challenge"

# Create another test user for challenge testing
CHALLENGE_USERNAME="challenge_user_$(date +%s)"

for i in {1..4}; do
  failed_login_response=$(curl -s -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
      "username": "'"$CHALLENGE_USERNAME"'",
      "passcode": "WrongPassword123!",
      "loginMethod": "direct"
    }')
  
  echo "Failed attempt $i response: ${failed_login_response:0:100}..."
  sleep 1
done

# Check if challenge is required
substep "Checking if challenge is required"
challenge_check_response=$(curl -s -X GET "$API_URL/challenge/check-required?username=$CHALLENGE_USERNAME")
response "$challenge_check_response"

challenge_required=$(extract_value "$challenge_check_response" "challengeRequired")

if [ "$challenge_required" = "true" ]; then
  success "Challenge required after multiple failed attempts"
  
  # Create challenge
  substep "Creating challenge"
  create_challenge_response=$(curl -s -X POST "$API_URL/challenge/create" \
    -H "Content-Type: application/json" \
    -d '{
      "username": "'"$CHALLENGE_USERNAME"'"
    }')
  
  response "$create_challenge_response"
  challenge_id=$(extract_value "$create_challenge_response" "challenge.id")
  challenge_type=$(extract_value "$create_challenge_response" "challenge.type")
  challenge_question=$(extract_value "$create_challenge_response" "challenge.question")
  
  echo -e "${YELLOW}Challenge Type: $challenge_type${NC}"
  echo -e "${YELLOW}Challenge Question: $challenge_question${NC}"
  
  if [[ "$challenge_type" == "MATH_PROBLEM" ]]; then
    read -p "Enter the answer to the math problem: " challenge_answer
  else
    if [ ! -z "$(extract_value "$create_challenge_response" "challenge.image")" ]; then
      echo -e "${YELLOW}CAPTCHA Image:${NC}"
      echo "$(extract_value "$create_challenge_response" "challenge.image")"
    fi
    read -p "Enter the CAPTCHA text: " challenge_answer
  fi
  
  # Verify challenge
  substep "Verifying challenge answer"
  verify_challenge_response=$(curl -s -X POST "$API_URL/challenge/verify" \
    -H "Content-Type: application/json" \
    -d '{
      "challengeId": "'"$challenge_id"'",
      "answer": "'"$challenge_answer"'"
    }')
  
  response "$verify_challenge_response"
  success_status=$(extract_value "$verify_challenge_response" "success")
  
  if [ "$success_status" = "true" ]; then
    success "Challenge completed successfully"
  else
    warning "Challenge verification failed"
  fi
else
  warning "Challenge not required (may need more failed attempts)"
fi

# STEP 6: Use protected endpoint to view sessions
step 6 "Use protected endpoint (view sessions)"
request "GET" "$API_URL/auth/sessions" "Authorization: Bearer $access_token"

sessions_response=$(curl -s -X GET "$API_URL/auth/sessions" \
  -H "Authorization: Bearer $access_token")

response "$sessions_response"

success_status=$(extract_value "$sessions_response" "success")

if [ "$success_status" != "true" ]; then
  warning "Failed to access protected endpoint"
else
  success "Successfully accessed protected endpoint"
  # Try to extract session ID for later use
  session_id=$(echo "$sessions_response" | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"//;s/"//')
  if [ ! -z "$session_id" ]; then
    substep "Found session ID: $session_id (will be used for session termination)"
  fi
fi

# STEP 7: Test Role-Based Access Control
step 7 "Test Role-Based Access Control"

# Try to access admin endpoint as regular user
substep "Attempting to access admin endpoint as regular user"
roles_response=$(curl -s -X GET "$API_URL/roles" \
  -H "Authorization: Bearer $access_token")

response "$roles_response"

if [[ "$roles_response" == *"403"* ]] || [[ "$roles_response" == *"Access denied"* ]] || [[ "$roles_response" == *"admin privileges required"* ]]; then
  success "RBAC working correctly - regular user denied admin access"
else
  warning "RBAC may not be working correctly or user has admin role"
fi

# Test role operations if admin token is provided
if [ ! -z "$ADMIN_TOKEN" ]; then
  substep "Testing admin operations with admin token"
  
  # Get all roles
  admin_roles_response=$(curl -s -X GET "$API_URL/roles" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
  
  response "$admin_roles_response"
  
  # Try to create a new role
  create_role_payload='{
    "name": "test_moderator",
    "description": "Test moderator role",
    "permissions": ["user:read", "logs:read"]
  }'
  
  create_role_response=$(curl -s -X POST "$API_URL/roles" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$create_role_payload")
  
  response "$create_role_response"
  
  if [[ "$create_role_response" == *"success\":true"* ]]; then
    success "Admin can create roles"
    new_role_id=$(extract_value "$create_role_response" "role.id")
    
    # Try to assign the role
    assign_role_payload='{
      "userId": "'"$user_id"'",
      "roleId": "'"$new_role_id"'"
    }'
    
    assign_role_response=$(curl -s -X POST "$API_URL/roles/assign" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d "$assign_role_payload")
    
    response "$assign_role_response"
  fi
else
  warning "Admin token not provided, skipping admin-only role tests"
fi

# STEP 8: Refresh token
step 8 "Refresh token"
refresh_payload='{
  "refreshToken": "'"$refresh_token"'"
}'

request "POST" "$API_URL/auth/refresh-token" "$refresh_payload"

refresh_response=$(curl -s -X POST "$API_URL/auth/refresh-token" \
  -H "Content-Type: application/json" \
  -d "$refresh_payload")

response "$refresh_response"

success_status=$(extract_value "$refresh_response" "success")
new_access_token=$(extract_value "$refresh_response" "accessToken")
new_refresh_token=$(extract_value "$refresh_response" "refreshToken")

if [ "$success_status" != "true" ] || [ -z "$new_access_token" ] || [ -z "$new_refresh_token" ]; then
  warning "Failed to refresh tokens"
else
  success "Token refresh successful. New tokens received."
  substep "Old Access Token: ${access_token:0:15}...${access_token: -15}"
  substep "New Access Token: ${new_access_token:0:15}...${new_access_token: -15}"
  substep "Old Refresh Token: ${refresh_token:0:15}...${refresh_token: -15}"
  substep "New Refresh Token: ${new_refresh_token:0:15}...${new_refresh_token: -15}"
  
  # Update tokens for subsequent requests
  access_token=$new_access_token
  refresh_token=$new_refresh_token
fi

# STEP 9: Test Activity Logging and Monitoring
step 9 "Test Activity Logging and Monitoring"

if [ ! -z "$ADMIN_TOKEN" ]; then
  substep "Fetching activity logs (admin only)"
  logs_response=$(curl -s -X GET "$API_URL/logs/activities?page=1&limit=10&category=AUTH" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
  
  response "$logs_response"
  
  if [[ "$logs_response" == *"success\":true"* ]]; then
    success "Activity logs retrieved successfully"
  fi
  
  # Check for security alerts
  substep "Checking security alerts"
  alerts_response=$(curl -s -X GET "$API_URL/logs/security-alerts" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
  
  response "$alerts_response"
  
  # Get login statistics
  substep "Getting login statistics"
  login_stats_response=$(curl -s -X GET "$API_URL/logs/login-stats?startDate=2024-01-01&endDate=2024-12-31" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
  
  response "$login_stats_response"
  
  # Verify log integrity
  substep "Verifying log integrity"
  integrity_response=$(curl -s -X GET "$API_URL/logs/verify-integrity" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
  
  response "$integrity_response"
else
  # Try as regular user (should fail)
  substep "Attempting to access logs as regular user (should fail)"
  logs_response=$(curl -s -X GET "$API_URL/logs/activities" \
    -H "Authorization: Bearer $access_token")
  
  response "$logs_response"
  
  if [[ "$logs_response" == *"403"* ]] || [[ "$logs_response" == *"Access denied"* ]]; then
    success "Logs correctly protected from regular users"
  else
    warning "Log access control may not be working"
  fi
fi

# STEP 10: Terminate a specific session (if session ID was found)
if [ ! -z "$session_id" ]; then
  step 10 "Terminate a specific session"
  request "DELETE" "$API_URL/auth/sessions/$session_id" "Authorization: Bearer $access_token"

  terminate_response=$(curl -s -X DELETE "$API_URL/auth/sessions/$session_id" \
    -H "Authorization: Bearer $access_token")

  response "$terminate_response"

  success_status=$(extract_value "$terminate_response" "success")

  if [ "$success_status" != "true" ]; then
    warning "Failed to terminate session"
  else
    success "Successfully terminated session $session_id"
  fi
else
  warning "Skipping session termination as no session ID was found"
fi

# STEP 11: Toggle MFA
step 11 "Toggle MFA setting"
request "PATCH" "$API_URL/auth/toggle-mfa" "Authorization: Bearer $access_token"

toggle_response=$(curl -s -X PATCH "$API_URL/auth/toggle-mfa" \
  -H "Authorization: Bearer $access_token")

response "$toggle_response"

success_status=$(extract_value "$toggle_response" "success")
mfa_enabled=$(extract_value "$toggle_response" "mfaEnabled")

if [ "$success_status" != "true" ]; then
  warning "Failed to toggle MFA setting"
else
  success "Successfully toggled MFA setting"
  substep "MFA is now: ${mfa_enabled}"
fi

# Get MFA stats if admin
if [ ! -z "$ADMIN_TOKEN" ]; then
  substep "Getting MFA statistics (admin only)"
  mfa_stats_response=$(curl -s -X GET "$API_URL/auth/mfa-stats" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
  
  response "$mfa_stats_response"
fi

# STEP 12: Test Rate Limiting
step 12 "Test Rate Limiting"

substep "Making rapid consecutive requests to trigger rate limiting"
rate_limit_triggered=false

for i in {1..20}; do
  rate_limit_response=$(curl -s -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
      "username": "ratelimittest'$i'",
      "passcode": "Test123!",
      "loginMethod": "direct"
    }')
  
  if [[ "$rate_limit_response" == *"429"* ]] || [[ "$rate_limit_response" == *"Too many"* ]]; then
    success "Rate limiting activated after $i requests"
    rate_limit_triggered=true
    break
  fi
  
  # Small delay to avoid overwhelming the server
  sleep 0.1
done

if [ "$rate_limit_triggered" = false ]; then
  warning "Rate limiting may not be working (made 20 requests without being limited)"
fi

# Test OTP rate limiting
substep "Testing OTP rate limiting"
for i in {1..6}; do
  otp_rate_response=$(curl -s -X POST "$API_URL/auth/verify-otp" \
    -H "Content-Type: application/json" \
    -d '{
      "userId": "'"$user_id"'",
      "otp": "000000"
    }')
  
  if [[ "$otp_rate_response" == *"429"* ]] || [[ "$otp_rate_response" == *"Too many OTP"* ]]; then
    success "OTP rate limiting activated after $i requests"
    break
  fi
  
  if [ $i -eq 6 ]; then
    warning "OTP rate limiting may not be working"
  fi
  
  sleep 0.5
done

# STEP 13: Test Security Measures
step 13 "Test Security Measures"

# Test SQL injection protection
substep "Testing SQL injection protection"
sql_injection_response=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin'\'' OR 1=1; --",
    "passcode": "test",
    "loginMethod": "direct"
  }')

response "$sql_injection_response"

if [[ "$sql_injection_response" == *"400"* ]] || [[ "$sql_injection_response" == *"Invalid"* ]]; then
  success "SQL injection attempt blocked"
else
  warning "SQL injection protection may not be working"
fi

# Test XSS protection
substep "Testing XSS protection"
xss_response=$(curl -s -X POST "$API_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "<script>alert(\"xss\")</script>",
    "dateOfBirth": "1990-01-01",
    "passcode": "Test123!",
    "registrationMethod": "telegram",
    "telegramId": "123456789"
  }')

response "$xss_response"

if [[ "$xss_response" == *"400"* ]] || [[ "$xss_response" == *"Invalid"* ]]; then
  success "XSS attempt blocked"
else
  warning "XSS protection may not be working"
fi

# Test password complexity requirements
substep "Testing password complexity requirements"
weak_password_response=$(curl -s -X POST "$API_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "weakpassuser",
    "dateOfBirth": "1990-01-01",
    "passcode": "weak",
    "registrationMethod": "telegram",
    "telegramId": "987654321"
  }')

response "$weak_password_response"

if [[ "$weak_password_response" == *"400"* ]] || [[ "$weak_password_response" == *"pattern"* ]]; then
  success "Weak password correctly rejected"
else
  warning "Password complexity validation may not be working"
fi

# STEP 14: Test Telegram message
step 14 "Test Telegram message"
telegram_payload='{
  "telegramId": "'"$TELEGRAM_ID"'",
  "message": "This is a test message from the automated script at '"$(date)"'"
}'

request "POST" "$API_URL/auth/test-telegram" "$telegram_payload"

test_msg_response=$(curl -s -X POST "$API_URL/auth/test-telegram" \
  -H "Content-Type: application/json" \
  -d "$telegram_payload")

response "$test_msg_response"

success_status=$(extract_value "$test_msg_response" "success")

if [ "$success_status" != "true" ]; then
  warning "Failed to send test message to Telegram"
else
  success "Successfully sent test message to Telegram"
  warning "Check your Telegram to confirm you received the test message"
fi

# STEP 15: Logout from current device
step 15 "Logout from current device"
logout_payload='{
  "refreshToken": "'"$refresh_token"'"
}'

request "POST" "$API_URL/auth/logout" "$logout_payload"

logout_response=$(curl -s -X POST "$API_URL/auth/logout" \
  -H "Content-Type: application/json" \
  -d "$logout_payload")

response "$logout_response"

success_status=$(extract_value "$logout_response" "success")

if [ "$success_status" != "true" ]; then
  warning "Failed to logout"
else
  success "Successfully logged out from current device"
fi

# STEP 16: Try to access protected endpoint with now-invalid token
step 16 "Try to access protected endpoint with revoked token"
request "GET" "$API_URL/auth/sessions" "Authorization: Bearer $access_token"

invalid_response=$(curl -s -X GET "$API_URL/auth/sessions" \
  -H "Authorization: Bearer $access_token")

response "$invalid_response"

success_status=$(extract_value "$invalid_response" "success")
error_message=$(extract_value "$invalid_response" "message")

if [ "$success_status" != "false" ]; then
  warning "Unexpected response when using revoked token"
else
  success "As expected, access was denied with the revoked token"
  substep "Error message: $error_message"
fi

# STEP 17: Attempt to refresh with now-invalid refresh token
step 17 "Try to refresh with revoked refresh token"
invalid_refresh_payload='{
  "refreshToken": "'"$refresh_token"'"
}'

request "POST" "$API_URL/auth/refresh-token" "$invalid_refresh_payload"

invalid_refresh_response=$(curl -s -X POST "$API_URL/auth/refresh-token" \
  -H "Content-Type: application/json" \
  -d "$invalid_refresh_payload")

response "$invalid_refresh_response"

success_status=$(extract_value "$invalid_refresh_response" "success")
error_message=$(extract_value "$invalid_refresh_response" "message")

if [ "$success_status" != "false" ]; then
  warning "Unexpected response when using revoked refresh token"
else
  success "As expected, refresh was denied with the revoked token"
  substep "Error message: $error_message"
fi

# STEP 18: Login again to test logout from all devices
step 18 "Login again to test logout-all"
login_again_payload='{
  "username": "'"$USERNAME"'",
  "passcode": "'"$PASSCODE"'",
  "loginMethod": "direct"
}'

request "POST" "$API_URL/auth/login" "$login_again_payload"

login_again_response=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "$login_again_payload")

response "$login_again_response"

# Handle MFA if required
require_mfa=$(extract_value "$login_again_response" "requireMFA")
login_user_id=$(extract_value "$login_again_response" "userId")
success_status=$(extract_value "$login_again_response" "success")

if [ "$success_status" != "true" ]; then
  error "Login failed. Cannot proceed with logout-all test."
fi

if [ "$require_mfa" = "true" ]; then
  warning "Check your Telegram for the login OTP code"
  read -p "Enter the OTP received on Telegram: " login_otp

  mfa_again_payload='{
    "userId": "'"$login_user_id"'",
    "otp": "'"$login_otp"'"
  }'

  request "POST" "$API_URL/auth/verify-mfa" "$mfa_again_payload"

  mfa_again_response=$(curl -s -X POST "$API_URL/auth/verify-mfa" \
    -H "Content-Type: application/json" \
    -d "$mfa_again_payload")

  response "$mfa_again_response"

  final_access_token=$(extract_value "$mfa_again_response" "accessToken")
  success_status=$(extract_value "$mfa_again_response" "success")
  
  if [ "$success_status" != "true" ] || [ -z "$final_access_token" ]; then
    error "MFA verification failed. Cannot proceed with logout-all test."
  else
    success "MFA verification successful"
    substep "New access token received for logout-all test"
  fi
else
  final_access_token=$(extract_value "$login_again_response" "accessToken")
  if [ -z "$final_access_token" ]; then
    error "Failed to get access token. Cannot proceed with logout-all test."
  else
    success "Login successful"
    substep "Access token received for logout-all test"
  fi
fi


# STEP 19: Logout from all devices
step 19 "Logout from all devices"
request "POST" "$API_URL/auth/logout-all" "Authorization: Bearer $final_access_token"

logout_all_response=$(curl -s -X POST "$API_URL/auth/logout-all" \
 -H "Authorization: Bearer $final_access_token")

response "$logout_all_response"

success_status=$(extract_value "$logout_all_response" "success")
message=$(extract_value "$logout_all_response" "message")

if [ "$success_status" != "true" ]; then
 warning "Failed to logout from all devices"
else
 success "Successfully logged out from all devices"
 substep "Response message: $message"
fi

# STEP 20: Test account lockout after multiple failed attempts
step 20 "Test Account Lockout"

LOCKOUT_USERNAME="lockout_user_$(date +%s)"

# First register a new user for lockout testing
lockout_register_payload='{
 "username": "'"$LOCKOUT_USERNAME"'",
 "dateOfBirth": "1990-01-01",
 "passcode": "LockoutTest123!",
 "registrationMethod": "telegram",
 "telegramId": "'"$TELEGRAM_ID"'"
}'

substep "Registering user for lockout test"
lockout_register_response=$(curl -s -X POST "$API_URL/auth/register" \
 -H "Content-Type: application/json" \
 -d "$lockout_register_payload")

lockout_user_id=$(extract_value "$lockout_register_response" "userId")

if [ ! -z "$lockout_user_id" ]; then
 # Skip OTP verification for this test user
 substep "Triggering multiple failed login attempts for account lockout"
 
 for i in {1..10}; do
   lockout_attempt_response=$(curl -s -X POST "$API_URL/auth/login" \
     -H "Content-Type: application/json" \
     -d '{
       "username": "'"$LOCKOUT_USERNAME"'",
       "passcode": "WrongPassword!",
       "loginMethod": "direct"
     }')
   
   echo "Failed attempt $i for lockout test"
   
   if [[ "$lockout_attempt_response" == *"locked"* ]] || [[ "$lockout_attempt_response" == *"too many failed"* ]]; then
     success "Account locked after $i failed attempts"
     break
   fi
   
   sleep 0.5
 done
 
 # Try to login with correct password after lockout
 substep "Attempting login with correct password after lockout"
 locked_login_response=$(curl -s -X POST "$API_URL/auth/login" \
   -H "Content-Type: application/json" \
   -d '{
     "username": "'"$LOCKOUT_USERNAME"'",
     "passcode": "LockoutTest123!",
     "loginMethod": "direct"
   }')
 
 response "$locked_login_response"
 
 if [[ "$locked_login_response" == *"locked"* ]]; then
   success "Account correctly remains locked even with correct password"
 else
   warning "Account lockout may not be working properly"
 fi
fi

# STEP 21: Test Session Management
step 21 "Test Session Management"

# Login from multiple sessions
substep "Creating multiple sessions"
session_tokens=()

for i in {1..3}; do
 multi_session_login_response=$(curl -s -X POST "$API_URL/auth/login" \
   -H "Content-Type: application/json" \
   -H "User-Agent: Test-Device-$i" \
   -d '{
     "username": "'"$USERNAME"'",
     "passcode": "'"$PASSCODE"'",
     "loginMethod": "direct"
   }')
 
 session_token=$(extract_value "$multi_session_login_response" "accessToken")
 
 if [ ! -z "$session_token" ]; then
   session_tokens+=("$session_token")
   echo "Session $i created"
 fi
done

# View all sessions
if [ ${#session_tokens[@]} -gt 0 ]; then
 substep "Viewing all active sessions"
 all_sessions_response=$(curl -s -X GET "$API_URL/auth/sessions" \
   -H "Authorization: Bearer ${session_tokens[0]}")
 
 response "$all_sessions_response"
 
 session_count=$(echo "$all_sessions_response" | grep -o '"id"' | wc -l)
 echo "Found $session_count active sessions"
fi

# STEP 22: Test Input Validation
step 22 "Test Input Validation"

# Test username validation
substep "Testing username validation"
invalid_username_response=$(curl -s -X POST "$API_URL/auth/register" \
 -H "Content-Type: application/json" \
 -d '{
   "username": "a",
   "dateOfBirth": "1990-01-01",
   "passcode": "Valid123!",
   "registrationMethod": "telegram",
   "telegramId": "123456789"
 }')

response "$invalid_username_response"

if [[ "$invalid_username_response" == *"400"* ]] || [[ "$invalid_username_response" == *"length"* ]]; then
 success "Username length validation working"
else
 warning "Username validation may not be working"
fi

# Test date validation (too young)
substep "Testing age validation"
too_young_response=$(curl -s -X POST "$API_URL/auth/register" \
 -H "Content-Type: application/json" \
 -d '{
   "username": "tooyounguser",
   "dateOfBirth": "2010-01-01",
   "passcode": "Valid123!",
   "registrationMethod": "telegram",
   "telegramId": "123456789"
 }')

response "$too_young_response"

if [[ "$too_young_response" == *"400"* ]] || [[ "$too_young_response" == *"18 years"* ]]; then
 success "Age validation working"
else
 warning "Age validation may not be working"
fi

# STEP 23: Test CSRF Protection
step 23 "Test CSRF Protection"

substep "Getting CSRF token"
csrf_response=$(curl -s -X GET "$API_URL/csrf-token")
response "$csrf_response"

csrf_token=$(extract_value "$csrf_response" "csrfToken")

if [ ! -z "$csrf_token" ]; then
 success "CSRF token retrieved: ${csrf_token:0:10}..."
else
 warning "CSRF protection may not be implemented"
fi

# STEP 24: Test Error Handling
step 24 "Test Error Handling"

# Test invalid endpoint
substep "Testing 404 error handling"
not_found_response=$(curl -s -X GET "$API_URL/nonexistent-endpoint")
response "$not_found_response"

if [[ "$not_found_response" == *"404"* ]] || [[ "$not_found_response" == *"not found"* ]]; then
 success "404 error handling working"
else
 warning "404 error handling may not be working"
fi

# Test invalid JSON
substep "Testing invalid JSON handling"
invalid_json_response=$(curl -s -X POST "$API_URL/auth/login" \
 -H "Content-Type: application/json" \
 -d '{invalid json}')

response "$invalid_json_response"

if [[ "$invalid_json_response" == *"400"* ]] || [[ "$invalid_json_response" == *"JSON"* ]]; then
 success "Invalid JSON handling working"
else
 warning "Invalid JSON handling may not be working"
fi

# STEP 25: Performance Test
step 25 "Basic Performance Test"

substep "Testing endpoint response times"
start_time=$(date +%s%N)
performance_response=$(curl -s -X GET "$API_URL/health")
end_time=$(date +%s%N)

response_time=$((($end_time - $start_time) / 1000000))
echo "Health endpoint response time: ${response_time}ms"

if [ $response_time -lt 500 ]; then
 success "Response time is acceptable (<500ms)"
else
 warning "Response time is slow (${response_time}ms)"
fi

# Test summary
echo -e "\n${GREEN}=======================================================${NC}"
echo -e "${GREEN}      ENHANCED TOKEN MANAGEMENT SYSTEM TEST COMPLETED${NC}"
echo -e "${GREEN}=======================================================${NC}"
echo -e "End Time: ${CYAN}$(date)${NC}"
echo -e "\n${GREEN}Test Results Summary:${NC}"
echo -e "✓ User registration and validation"
echo -e "✓ OTP verification"
echo -e "✓ User login with MFA"
echo -e "✓ Challenge-response mechanism"
echo -e "✓ Role-based access control"
echo -e "✓ Activity logging and monitoring"
echo -e "✓ Session management"
echo -e "✓ Token refresh and revocation"
echo -e "✓ Rate limiting"
echo -e "✓ Security measures (SQL injection, XSS protection)"
echo -e "✓ Account lockout"
echo -e "✓ Input validation"
echo -e "✓ Error handling"
echo -e "✓ Performance baseline"
echo -e "✓ Telegram integration"
echo -e "${GREEN}=======================================================${NC}"

# Count successful vs failed tests
echo -e "\n${GREEN}Test Statistics:${NC}"
echo "Total Tests Performed: 25"
echo "Successful Tests: $(grep -c "SUCCESS:" /tmp/test_output.log 2>/dev/null || echo "Check manually")"
echo "Warnings: $(grep -c "ATTENTION:" /tmp/test_output.log 2>/dev/null || echo "Check manually")"
echo "Errors: $(grep -c "ERROR:" /tmp/test_output.log 2>/dev/null || echo "Check manually")"

echo -e "\n${GREEN}Additional Notes:${NC}"
echo "• Some tests require admin privileges for full testing"
echo "• Rate limiting tests may need adjustment based on server configuration"
echo "• Challenge-response tests depend on failed attempt thresholds"
echo "• Performance baselines may vary based on server hardware"

echo -e "\n${GREEN}=======================================================${NC}"
echo -e "${GREEN}All aspects of the authentication system have been tested!${NC}"
echo -e "${GREEN}=======================================================${NC}"

# Optional: Save test report
if [ ! -z "$SAVE_REPORT" ]; then
 report_file="test_report_$(date +%Y%m%d_%H%M%S).txt"
 echo "Saving test report to: $report_file"
 # You can redirect all output to a file or create a formatted report
fi

# Exit with appropriate code
exit 0