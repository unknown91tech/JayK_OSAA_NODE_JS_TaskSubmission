const express = require('express');
const router = express.Router();
const {
  createUserChallenge,
  verifyChallengeAnswer,
  getChallengeStatistics,
  checkChallengeRequired
} = require('../controllers/challengeController');

const { 
  authenticateToken, 
  isAdmin 
} = require('../middlewares/auth');

const { 
  apiLimiter,
  strictRateLimiter 
} = require('../middlewares/rateLimiter');

const {
  sqlInjectionProtection,
  xssProtection,
  suspiciousActivityMonitor
} = require('../middlewares/security');

// Apply security middlewares to all challenge routes
router.use(sqlInjectionProtection);
router.use(xssProtection);
router.use(suspiciousActivityMonitor);

// Public routes (no authentication required)
// Check if challenge is required for a user/IP
router.get('/check-required', 
  apiLimiter,
  checkChallengeRequired
);

// Create a new challenge
router.post('/create', 
  apiLimiter,
  createUserChallenge
);

// Verify challenge answer
router.post('/verify', 
  apiLimiter,
  verifyChallengeAnswer
);

// Admin-only routes
// Get challenge statistics
router.get('/statistics', 
  authenticateToken,
  isAdmin,
  getChallengeStatistics
);

module.exports = router;