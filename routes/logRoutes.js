const express = require('express');
const router = express.Router();
const logController = require('../controllers/logController');
const { authenticateToken, isAdmin } = require('../middlewares/auth');

// All routes require authentication and admin privileges
router.use(authenticateToken);
router.use(isAdmin);

// Get activity logs with filtering and pagination
router.get('/activities', logController.getActivityLogs);

// Get log metadata for filtering
router.get('/metadata', logController.getLogMetadata);

// Get user activity summary
router.get('/user/:userId', logController.getUserActivitySummary);

// Get security alerts
router.get('/security-alerts', logController.getSecurityAlerts);

// Run log integrity verification
router.get('/verify-integrity', logController.verifyLogIntegrity);

// Get raw log file
router.get('/raw/:category/:date', logController.getRawLogFile);

// Get login statistics
router.get('/login-stats', logController.getLoginStats);

module.exports = router;