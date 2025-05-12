# Secure Authentication System

A robust, production-ready authentication system built with Node.js, Express, PostgreSQL, and Sequelize. Features include multi-factor authentication (MFA), role-based access control (RBAC), comprehensive logging, and security measures against common attacks.

## 🚀 Features

- **User Authentication**
  - Secure registration and login with bcrypt password hashing
  - Multi-factor authentication (MFA) via Telegram/WhatsApp
  - JWT-based token authentication with refresh tokens
  - Account lockout after failed attempts
  
- **Security**
  - Rate limiting on all endpoints
  - SQL injection protection
  - XSS protection
  - CSRF protection
  - Request fingerprinting
  - Challenge/CAPTCHA system for suspicious activity
  
- **Role Management**
  - Role-based access control (RBAC)
  - Dynamic permission assignment
  - Admin, User, and Moderator roles
  
- **Logging & Monitoring**
  - Comprehensive activity logging
  - Security event tracking
  - Log file integrity verification
  - Automatic log rotation and archiving
  
- **Additional Features**
  - Telegram bot integration for OTP delivery
  - Session management across devices
  - Graceful error handling
  - Database health checks

## 📋 Prerequisites

- Node.js v14+ 
- PostgreSQL 12+
- Redis (optional, for session storage)
- Telegram Bot Token (for MFA)

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone (https://github.com/unknown91tech/JayK_OSAA_NODE_JS_TaskSubmission.git)
   cd auth-system
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` with your configuration:
   ```env
   
    # Server Configuration
    PORT=3000
    NODE_ENV=development

    # Database Configuration (Neon Postgres)
    DATABASE_URL=

    # JWT Secret
    JWT_SECRET=your_jwt_secret_key_here

    # Telegram Bot Configuration
    TELEGRAM_BOT_TOKEN=7847330646:AAGzWMaNfwAXP7wNrO88LtlMjTS-lZ-5TQg

    # Rate Limiting
    RATE_LIMIT_WINDOW_MS=900000  # 15 minutes
    RATE_LIMIT_MAX_REQUESTS=100

    # Token Expiry (in milliseconds)
    ACCESS_TOKEN_EXPIRY=3600000   # 1 hour
    REFRESH_TOKEN_EXPIRY=604800000  # 7 days

    # Logging Configuration
    LOG_DIR=./logs
    LOG_ROTATION_SIZE=10485760  # 10MB in bytes
    LOG_RETENTION_DAYS=90       # Number of days to keep logs
    ADMIN_TELEGRAM_IDS=123456789  # Comma-separated list of admin Telegram IDs

   ```

## 🚀 Running the Application

### Development
```bash
npm run dev
```

### Production
```bash
npm start
```

## 🧪 Testing

### Run Complete Integration Test Suite

The project includes a comprehensive test script that validates all features of the authentication system.

1. **Make the script executable**
   ```bash
   chmod +x main.sh
   ```

2. **Configure test parameters**
   
   Edit `main.sh` to update your test configuration:
   ```bash
   # Configuration - Update these values
   API_URL="http://localhost:3000/api"
   TELEGRAM_ID="1234567890" # Replace with your actual Telegram ID
   ADMIN_TOKEN=""  # Optional: Set this if you have admin access
   ```

3. **Run the complete test suite**
   ```bash
   ./main.sh
   ```

The test script will automatically:
- Register a new test user
- Verify OTP via Telegram
- Test login with MFA
- Validate challenge-response mechanism
- Test role-based access control
- Verify activity logging
- Test rate limiting
- Validate security measures
- Test session management
- Check account lockout mechanisms
- And much more...

The script provides colored output and detailed feedback for each test step, making it easy to identify any issues.

### Test Coverage Includes

1. **User Registration Process**
   - OTP collection from Telegram
   - Input validation
   - Duplicate account prevention
   - UUID generation

2. **Authentication & MFA**
   - Login attempts (successful/failed)
   - OTP generation and validation
   - Rate limiting enforcement
   - Account lockout after threshold

3. **Role-Based Access Control**
   - Default role assignment
   - Access restrictions by role
   - Admin vs user permissions

4. **Security Protocols**
   - SQL injection prevention
   - XSS protection
   - Password complexity requirements
   - Rate limiting on all sensitive endpoints

5. **Token Management**
   - JWT generation and expiration
   - Token refresh mechanism
   - Session revocation

6. **Challenge-Response System**
   - CAPTCHA generation after failed attempts
   - Math problem challenges
   - Verification workflow

7. **Logging & Monitoring**
   - Activity log generation
   - Security alert detection
   - Log integrity verification



## 📡 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/verify-otp` - Verify OTP
- `POST /api/auth/login` - User login
- `POST /api/auth/verify-mfa` - Verify MFA code
- `POST /api/auth/refresh-token` - Refresh access token
- `POST /api/auth/logout` - Logout user
- `POST /api/auth/logout-all` - Logout from all devices
- `GET /api/auth/sessions` - Get active sessions
- `DELETE /api/auth/sessions/:sessionId` - Terminate specific session
- `PATCH /api/auth/toggle-mfa` - Toggle MFA setting

### Challenges
- `GET /api/challenge/check-required` - Check if challenge required
- `POST /api/challenge/create` - Create new challenge
- `POST /api/challenge/verify` - Verify challenge answer

### Roles (Admin only)
- `GET /api/roles` - Get all roles
- `GET /api/roles/:id` - Get role by ID
- `POST /api/roles` - Create new role
- `PUT /api/roles/:id` - Update role
- `DELETE /api/roles/:id` - Delete role
- `POST /api/roles/assign` - Assign role to user
- `POST /api/roles/remove` - Remove role from user
- `GET /api/roles/user/:userId` - Get user's roles
- `GET /api/roles/:roleId/users` - Get users with role

### Logs (Admin only)
- `GET /api/logs/activities` - Get activity logs
- `GET /api/logs/metadata` - Get log metadata
- `GET /api/logs/user/:userId` - Get user activity summary
- `GET /api/logs/security-alerts` - Get security alerts
- `GET /api/logs/verify-integrity` - Verify log integrity
- `GET /api/logs/raw/:category/:date` - Get raw log file
- `GET /api/logs/login-stats` - Get login statistics

## 🔧 Configuration

### Telegram Bot Setup

1. Create a new bot with [BotFather](https://t.me/botfather)
2. Get the bot token
3. Add the token to your `.env` file
4. Start a conversation with your bot


### Log Rotation

Logs are automatically rotated daily. To manually rotate:
```bash
npm run rotate-logs
```

## 📂 Project Structure

```
.
├── config/             # Configuration files
├── controllers/        # Route controllers
├── middlewares/        # Express middlewares
├── models/            # Sequelize models
├── routes/            # API routes
├── services/          # Business logic
├── utils/             # Utility functions
├── scripts/           # CLI scripts
├── schedulers/        # Cron jobs
├── tests/             # Test files
├── logs/              # Log files
├── app.js             # Express app
├── server.js          # Server entry point
├── main.sh            # Comprehensive test script
├── .env.example       # Environment variables example
├── package.json       # Dependencies
└── README.md          # Documentation
```

## 🔐 Security Considerations

1. **Environment Variables**: Never commit `.env` file
2. **HTTPS**: Always use HTTPS in production
3. **Rate Limiting**: Adjust limits based on your needs
4. **CORS**: Configure allowed origins properly
5. **SQL Injection**: Use parameterized queries
6. **XSS**: Sanitize all user inputs
7. **CSRF**: Use CSRF tokens for state-changing operations

## 📊 Monitoring

### Health Check
```bash
curl http://localhost:3000/health
```
### Swagger Check
```bash
curl http://localhost:3000/api-docs
```

### Logs
- Application logs: `./logs/`
- Security alerts: Check through the API or log files
- Integrity verification: Run periodically

### Metrics
- Login attempts and success rates
- API response times
- Error rates
- Active sessions

## 🐛 Troubleshooting

### Common Issues

1. **Telegram OTP not received**
   - Ensure you've started a conversation with your bot
   - Check the Telegram Bot Token is correct
   - Verify the Telegram ID matches your account

2. **Database connection errors**
   - Verify PostgreSQL is running
   - Check DATABASE_URL in .env
   - Ensure database exists

3. **Test script failures**
   - Make sure the server is running
   - Check API_URL in main.sh matches your server
   - Ensure Telegram bot is properly configured

4. **Rate limiting during tests**
   - Wait a few minutes between test runs
   - Adjust rate limits in middlewares/rateLimiter.js for testing

