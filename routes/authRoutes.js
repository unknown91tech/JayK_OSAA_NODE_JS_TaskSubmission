// routes/authRoutes.js - Updated with challenge support
const express = require('express');
const router = express.Router();
const { 
  registerUser, 
  verifyUserOTP, 
  testTelegramMessage,
  loginUser,
  verifyLoginMFA,
  toggleMFA,
  getMFAStats
} = require('../controllers/authController');

const {
  refreshUserTokens,
  logoutUser,
  logoutFromAllDevices,
  getUserSessions,
  terminateSession
} = require('../controllers/tokenController');

// Enhanced validation middleware with challenge support
const { 
  validateRegistration, 
  validateOTPVerification, 
  validateTelegramTest,
  validateLoginWithChallenge, // Updated login validation with challenge support
  validateMFAVerification,
  validateTokenRefresh,
  validateLogout,
  // Add new challenge validations
  validateChallengeCreation,
  validateChallengeVerification,
  validateChallengeCheck
} = require('../middlewares/validation');

// Enhanced rate limiting
const { 
  loginRateLimiter,
  otpRateLimiter,
  registrationRateLimiter,
  strictRateLimiter
} = require('../middlewares/rateLimiter');

// Security middlewares
const {
  sqlInjectionProtection,
  xssProtection,
  requestFingerprinting,
  suspiciousActivityMonitor
} = require('../middlewares/security');

// Authentication middlewares
const { 
  authenticateToken, 
  authenticateRefreshToken,
  isAdmin 
} = require('../middlewares/auth');

// Apply security middlewares to all auth routes
router.use(sqlInjectionProtection);
router.use(xssProtection);
router.use(requestFingerprinting);
router.use(suspiciousActivityMonitor);

// User registration endpoint with enhanced security
router.post('/register', 
  registrationRateLimiter,
  validateRegistration, 
  registerUser
);

// OTP verification endpoint with rate limiting
router.post('/verify-otp', 
  otpRateLimiter,
  validateOTPVerification, 
  verifyUserOTP
);

// Challenge-related endpoints
// Check if challenge is required for login
router.get('/challenge/check', 
  validateChallengeCheck,
  require('../controllers/challengeController').checkChallengeRequired
);

// Create a new challenge
router.post('/challenge/create', 
  validateChallengeCreation,
  require('../controllers/challengeController').createUserChallenge
);

// Verify challenge answer
router.post('/challenge/verify', 
  validateChallengeVerification,
  require('../controllers/challengeController').verifyChallengeAnswer
);

// User login endpoint with comprehensive protection and challenge support
router.post('/login', 
  validateLoginWithChallenge, // Updated validation
  loginRateLimiter, 
  loginUser
);

// MFA verification endpoint
router.post('/verify-mfa', 
  validateMFAVerification, 
  verifyLoginMFA
);

// Token refresh endpoint
router.post('/refresh-token', 
  validateTokenRefresh, 
  refreshUserTokens
);

// Logout endpoint
router.post('/logout', 
  validateLogout, 
  logoutUser
);

// Logout from all devices endpoint
router.post('/logout-all', 
  authenticateToken, 
  logoutFromAllDevices
);

// Get active sessions endpoint
router.get('/sessions', 
  authenticateToken, 
  getUserSessions
);

// Terminate specific session endpoint
router.delete('/sessions/:sessionId', 
  authenticateToken, 
  terminateSession
);

// Toggle MFA setting (requires authentication)
router.patch('/toggle-mfa', 
  authenticateToken, 
  strictRateLimiter,
  toggleMFA
);

// Test Telegram message endpoint
router.post('/test-telegram', 
  strictRateLimiter,
  validateTelegramTest, 
  testTelegramMessage
);

// Get MFA statistics (admin only)
router.get('/mfa-stats', 
  authenticateToken, 
  isAdmin, 
  getMFAStats
);

// Get challenge statistics (admin only)
router.get('/challenge-stats', 
  authenticateToken, 
  isAdmin,
  require('../controllers/challengeController').getChallengeStatistics
);

// Bot info endpoint (admin only)
router.get('/bot-info', 
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { bot } = require('../services/telegramService');
      const botInfo = await bot.getMe();
      res.status(200).json({
        success: true,
        botInfo
      });
    } catch (error) {
      console.error('❌ Error fetching bot info:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch bot info',
        error: error.message
      });
    }
  }
);

module.exports = router;