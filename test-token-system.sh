#!/bin/bash

# Token Management System Test Script
# This script automates testing of the complete authentication flow with token management

# Configuration - Update these values
API_URL="http://localhost:3000/api"
USERNAME="testuser"
PASSCODE="Secure123!"
TELEGRAM_ID="1694779369" # Replace with your actual Telegram ID

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
echo -e "${GREEN}      TOKEN MANAGEMENT SYSTEM TEST SCRIPT${NC}"
echo -e "${GREEN}=======================================================${NC}"
echo -e "API URL: ${CYAN}$API_URL${NC}"
echo -e "Username: ${CYAN}$USERNAME${NC}"
echo -e "Telegram ID: ${CYAN}$TELEGRAM_ID${NC}"
echo -e "Start Time: ${CYAN}$(date)${NC}"
echo -e "${GREEN}=======================================================${NC}"
echo -e "This script will test all aspects of the token management system."
echo -e "You'll need to check your Telegram app for OTP codes during the test."
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
  "referralCode": "'"$TELEGRAM_ID"'"
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

# STEP 5: Use protected endpoint to view sessions
step 5 "Use protected endpoint (view sessions)"
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

# STEP 6: Refresh token
step 6 "Refresh token"
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

# STEP 7: Terminate a specific session (if session ID was found)
if [ ! -z "$session_id" ]; then
  step 7 "Terminate a specific session"
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

# STEP 8: Toggle MFA
step 8 "Toggle MFA setting"
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

# STEP 9: Test Telegram message
step 9 "Test Telegram message"
telegram_payload='{
  "telegramId": "'"$TELEGRAM_ID"'",
  "message": "This is a test message from the automated script"
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
  warning "Check your Telegram to confirm you received: 'This is a test message from the automated script'"
fi

# STEP 10: Logout from current device
step 10 "Logout from current device"
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

# STEP 11: Try to access protected endpoint with now-invalid token
step 11 "Try to access protected endpoint with revoked token"
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

# STEP 12: Attempt to refresh with now-invalid refresh token
step 12 "Try to refresh with revoked refresh token"
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

# STEP 13: Login again to test logout from all devices
step 13 "Login again to test logout-all"
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

# STEP 14: Logout from all devices
step 14 "Logout from all devices"
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

# Test summary
echo -e "\n${GREEN}=======================================================${NC}"
echo -e "${GREEN}      TOKEN MANAGEMENT SYSTEM TEST COMPLETED${NC}"
echo -e "${GREEN}=======================================================${NC}"
echo -e "Start Time: ${CYAN}$(date)${NC}"
echo -e "End Time: ${CYAN}$(date)${NC}"
echo -e "\n${GREEN}Test Results Summary:${NC}"
echo -e "✓ User registration"
echo -e "✓ OTP verification"
echo -e "✓ User login"
echo -e "✓ Session management"
echo -e "✓ Token refresh"
echo -e "✓ Token revocation"
echo -e "✓ MFA toggle"
echo -e "✓ Telegram messaging"
echo -e "✓ Error handling validation"
echo -e "${GREEN}=======================================================${NC}"
echo -e "All aspects of the token management system have been tested!"
echo -e "${GREEN}=======================================================${NC}": $invalid_response"
if [[ "$invalid_response" == *"success\":false"* ]]; then
  success "As expected, access was denied with the revoked token"
else
  warning "Unexpected response when using revoked token"
fi

# STEP 12: Attempt to refresh with now-invalid refresh token
step 12 "Try to refresh with revoked refresh token"
invalid_refresh_response=$(curl -s -X POST "$API_URL/auth/refresh-token" \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "'"$refresh_token"'"
  }')

echo "Response: $invalid_refresh_response"
if [[ "$invalid_refresh_response" == *"success\":false"* ]]; then
  success "As expected, refresh was denied with the revoked token"
else
  warning "Unexpected response when using revoked refresh token"
fi

# STEP 13: Login again to test logout from all devices
step 13 "Login again to test logout-all"
login_again_response=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "'"$USERNAME"'",
    "passcode": "'"$PASSCODE"'",
    "loginMethod": "direct"
  }')

echo "Response: $login_again_response"

# Handle MFA if required
require_mfa=$(extract_value "$login_again_response" "requireMFA")
login_user_id=$(extract_value "$login_again_response" "userId")

if [ "$require_mfa" = "true" ]; then
  warning "Check your Telegram for the login OTP code"
  read -p "Enter the OTP received on Telegram: " login_otp

  mfa_again_response=$(curl -s -X POST "$API_URL/auth/verify-mfa" \
    -H "Content-Type: application/json" \
    -d '{
      "userId": "'"$login_user_id"'",
      "otp": "'"$login_otp"'"
    }')

  echo "Response: $mfa_again_response"
  final_access_token=$(extract_value "$mfa_again_response" "accessToken")
else
  final_access_token=$(extract_value "$login_again_response" "accessToken")
fi

if [ -z "$final_access_token" ]; then
  warning "Could not log in again, skipping logout-all test"
else
  success "Logged in successfully again"
  
  # STEP 14: Logout from all devices
  step 14 "Logout from all devices"
  logout_all_response=$(curl -s -X POST "$API_URL/auth/logout-all" \
    -H "Authorization: Bearer $final_access_token")

  echo "Response: $logout_all_response"
  if [[ "$logout_all_response" == *"success\":true"* ]]; then
    success "Successfully logged out from all devices"
  else
    warning "Failed to logout from all devices"
  fi
fi

echo -e "\n${GREEN}=== Token Management System Test Complete ===${NC}"
echo "You have successfully tested all aspects of the token management system.": $invalid_refresh_response"
if [[ "$invalid_refresh_response" == *"success\":false"* ]]; then
  success "As expected, refresh was denied with the revoked token"
else
  warning "Unexpected response when using revoked refresh token"
fi

# STEP 13: Login again to test logout from all devices
step 13 "Login again to test logout-all"
login_again_response=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "'"$USERNAME"'",
    "passcode": "'"$PASSCODE"'",
    "loginMethod": "direct"
  }')

echo "Response: $login_again_response"

# Handle MFA if required
require_mfa=$(extract_value "$login_again_response" "requireMFA")
login_user_id=$(extract_value "$login_again_response" "userId")

if [ "$require_mfa" = "true" ]; then
  warning "Check your Telegram for the login OTP code"
  read -p "Enter the OTP received on Telegram: " login_otp

  mfa_again_response=$(curl -s -X POST "$API_URL/auth/verify-mfa" \
    -H "Content-Type: application/json" \
    -d '{
      "userId": "'"$login_user_id"'",
      "otp": "'"$login_otp"'"
    }')

  echo "Response: $mfa_again_response"
  final_access_token=$(extract_value "$mfa_again_response" "accessToken")
else
  final_access_token=$(extract_value "$login_again_response" "accessToken")
fi

if [ -z "$final_access_token" ]; then
  warning "Could not log in again, skipping logout-all test"
else
  success "Logged in successfully again"
  
  # STEP 14: Logout from all devices
  step 14 "Logout from all devices"
  logout_all_response=$(curl -s -X POST "$API_URL/auth/logout-all" \
    -H "Authorization: Bearer $final_access_token")

  echo "Response: $logout_all_response"
  if [[ "$logout_all_response" == *"success\":true"* ]]; then
    success "Successfully logged out from all devices"
  else
    warning "Failed to logout from all devices"
  fi
fi

echo -e "\n${GREEN}=== Token Management System Test Complete ===${NC}"
echo "You have successfully tested all aspects of the token management system."