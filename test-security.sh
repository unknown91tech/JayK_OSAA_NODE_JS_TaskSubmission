#!/bin/bash
# scripts/test-security.sh - Test security features

BASE_URL="http://localhost:3000"
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${CYAN}🔒 Testing Security Features${NC}"
echo "================================="

# Test 1: XSS Protection
echo -e "\n${YELLOW}Test 1: XSS Protection${NC}"
response=$(curl -s -w "%{http_code}" -o /dev/null -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"<script>alert(\"xss\")</script>","dateOfBirth":"1990-01-01","passcode":"Password123!","registrationMethod":"telegram","telegramId":"123456789"}')

if [ "$response" -eq 400 ]; then
    echo -e "${GREEN}✅ XSS protection working - malicious script blocked${NC}"
else
    echo -e "${RED}❌ XSS protection failed - status code: $response${NC}"
fi

# Test 2: SQL Injection Protection
echo -e "\n${YELLOW}Test 2: SQL Injection Protection${NC}"
response=$(curl -s -w "%{http_code}" -o /dev/null -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin\"; DROP TABLE users; --","passcode":"password","loginMethod":"direct"}')

if [ "$response" -eq 400 ]; then
    echo -e "${GREEN}✅ SQL injection protection working - malicious query blocked${NC}"
else
    echo -e "${RED}❌ SQL injection protection failed - status code: $response${NC}"
fi

# Test 3: Password Validation
echo -e "\n${YELLOW}Test 3: Password Validation${NC}"
response=$(curl -s -w "%{http_code}" -o /dev/null -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","dateOfBirth":"1990-01-01","passcode":"weak","registrationMethod":"telegram","telegramId":"123456789"}')

if [ "$response" -eq 400 ]; then
    echo -e "${GREEN}✅ Password validation working - weak password rejected${NC}"
else
    echo -e "${RED}❌ Password validation failed - weak password accepted${NC}"
fi

# Test 4: Username Validation
echo -e "\n${YELLOW}Test 4: Username Validation${NC}"
response=$(curl -s -w "%{http_code}" -o /dev/null -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"user@#$%","dateOfBirth":"1990-01-01","passcode":"Password123!","registrationMethod":"telegram","telegramId":"123456789"}')

if [ "$response" -eq 400 ]; then
    echo -e "${GREEN}✅ Username validation working - invalid characters rejected${NC}"
else
    echo -e "${RED}❌ Username validation failed - invalid username accepted${NC}"
fi

# Test 5: Rate Limiting (Login)
echo -e "\n${YELLOW}Test 5: Rate Limiting (Login)${NC}"
echo "Making multiple failed login attempts..."

for i in {1..6}; do
    curl -s -o /dev/null -X POST "$BASE_URL/api/auth/login" \
      -H "Content-Type: application/json" \
      -d '{"username":"testuser","passcode":"wrongpassword","loginMethod":"direct"}'
done

response=$(curl -s -w "%{http_code}" -o /dev/null -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","passcode":"wrongpassword","loginMethod":"direct"}')

if [ "$response" -eq 429 ]; then
    echo -e "${GREEN}✅ Rate limiting working - too many attempts blocked${NC}"
else
    echo -e "${RED}❌ Rate limiting failed - status code: $response${NC}"
fi

# Test 6: Security Headers
echo -e "\n${YELLOW}Test 6: Security Headers${NC}"
headers=$(curl -s -I "$BASE_URL/")

if echo "$headers" | grep -q "X-Frame-Options"; then
    echo -e "${GREEN}✅ X-Frame-Options header present${NC}"
else
    echo -e "${RED}❌ X-Frame-Options header missing${NC}"
fi

if echo "$headers" | grep -q "Content-Security-Policy"; then
    echo -e "${GREEN}✅ Content-Security-Policy header present${NC}"
else
    echo -e "${RED}❌ Content-Security-Policy header missing${NC}"
fi

if echo "$headers" | grep -q "Strict-Transport-Security"; then
    echo -e "${GREEN}✅ HSTS header present${NC}"
else
    echo -e "${RED}❌ HSTS header missing${NC}"
fi

# Test 7: Request Size Limit
echo -e "\n${YELLOW}Test 7: Request Size Limit${NC}"
large_data=$(printf '%*s' 2000000 '' | tr ' ' 'a')
response=$(curl -s -w "%{http_code}" -o /dev/null -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"test\",\"dateOfBirth\":\"1990-01-01\",\"passcode\":\"Password123!\",\"registrationMethod\":\"telegram\",\"telegramId\":\"123456789\",\"largeField\":\"$large_data\"}")

if [ "$response" -eq 413 ] || [ "$response" -eq 400 ]; then
    echo -e "${GREEN}✅ Request size limit working - large request blocked${NC}"
else
    echo -e "${RED}❌ Request size limit failed - status code: $response${NC}"
fi

echo -e "\n${CYAN}Security Test Summary${NC}"
echo "===================="
echo "All tests completed. Check the logs for detailed security events."
echo ""
echo "To monitor security logs:"
echo "  tail -f logs/security_*.log | grep -E 'WARNING|ALERT|ERROR'"