const { logActivity, detectSuspiciousActivity } = require('../services/loggerService');
const { User } = require('../models');

// Log all restricted endpoint access
const logAccessMiddleware = (req, res, next) => {
  // Get original URL path
  const path = req.originalUrl;
  
  // Continue processing
  next();
  
  // This will execute after the request is processed
  const logData = {
    action: 'API_ACCESS',
    category: 'ACCESS',
    severity: 'INFO',
    details: {
      method: req.method,
      path: path,
      query: req.query,
      body: sanitizeRequestBody(req.body), // Remove sensitive data
      headers: sanitizeHeaders(req.headers) // Remove sensitive data
    },
    ipAddress: req.ip || req.connection.remoteAddress,
    userAgent: req.get('user-agent') || 'Unknown',
    resourceId: path,
    status: res.statusCode < 400 ? 'SUCCESS' : 'FAILURE',
    userId: req.user ? req.user.id : null
  };
  
  // Log the activity
  logActivity(logData).catch(err => console.error('Failed to log access:', err));
};

// Log all authentication events (login, logout, etc.)
const authEventLogger = action => {
  return async (req, res, originalJson) => {
    // Store the original res.json function
    const originalResJson = res.json;
    
    // Override res.json to capture response
    res.json = function(data) {
      // Restore original function right away
      res.json = originalResJson;
      
      // Set up log data
      const logData = {
        action: action,
        category: 'AUTH',
        severity: data.success ? 'INFO' : 'WARNING',
        details: {
          username: req.body.username,
          loginMethod: req.body.loginMethod,
          // Don't log passwords, OTPs, tokens
          tokenProvided: !!req.body.refreshToken,
          mfaRequired: data.requireMFA || false,
          reason: data.message
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: req.originalUrl,
        status: data.success ? 'SUCCESS' : 'FAILURE',
        userId: data.user ? data.user.id : null
      };
      
      // Log the activity
      logActivity(logData).catch(err => console.error(`Failed to log ${action}:`, err));
      
      // If login failed, check for suspicious activity
      if (action === 'LOGIN' && !data.success && req.body.username) {
        handleFailedLogin(req.body.username, req.ip).catch(err => 
          console.error('Failed to handle failed login:', err)
        );
      }
      
      // Call the original function
      return originalResJson.call(this, data);
    };
    
    // Continue processing
    if (typeof originalJson === 'function') {
      originalJson();
    } else {
      next();
    }
  };
};

// Log all OTP events
const otpEventLogger = (action, severity = 'INFO') => {
  return async (req, res, originalJson) => {
    // Store the original res.json function
    const originalResJson = res.json;
    
    // Override res.json to capture response
    res.json = function(data) {
      // Restore original function right away
      res.json = originalResJson;
      
      // Set up log data
      const logData = {
        action: action,
        category: 'MFA',
        severity: data.success ? severity : 'WARNING',
        details: {
          // Never log actual OTP values
          userId: req.body.userId,
          otpProvided: !!req.body.otp,
          reason: data.message
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: req.originalUrl,
        status: data.success ? 'SUCCESS' : 'FAILURE',
        userId: req.body.userId || null
      };
      
      // Log the activity
      logActivity(logData).catch(err => console.error(`Failed to log ${action}:`, err));
      
      // Call the original function
      return originalResJson.call(this, data);
    };
    
    // Continue processing
    if (typeof originalJson === 'function') {
      originalJson();
    } else {
      next();
    }
  };
};

// Helper function to sanitize request body (remove sensitive info)
const sanitizeRequestBody = (body) => {
  if (!body) return {};
  
  const sanitized = { ...body };
  
  // Remove sensitive fields
  const sensitiveFields = [
    'passcode', 'password', 'token', 'accessToken', 'refreshToken', 
    'otp', 'secret', 'apiKey', 'otpSecret'
  ];
  
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });
  
  return sanitized;
};

// Helper function to sanitize headers (remove sensitive info)
const sanitizeHeaders = (headers) => {
  if (!headers) return {};
  
  const sanitized = { ...headers };
  
  // Remove sensitive headers
  const sensitiveHeaders = [
    'authorization', 'cookie', 'x-api-key'
  ];
  
  sensitiveHeaders.forEach(header => {
    if (sanitized[header]) {
      sanitized[header] = '[REDACTED]';
    }
  });
  
  return sanitized;
};

// Handle failed login attempts and check for suspicious activity
const handleFailedLogin = async (username, ipAddress) => {
  try {
    // Get user ID if user exists
    const user = await User.findOne({ where: { username } });
    if (!user) return; // User doesn't exist, so we can't track attempts
    
    // Check for suspicious activity (5+ failures in 15 minutes)
    const isSuspicious = await detectSuspiciousActivity(user.id, 'LOGIN', 5);
    
    if (isSuspicious) {
      // Log security alert
      await logActivity({
        action: 'BRUTE_FORCE_ATTEMPT',
        category: 'SECURITY',
        severity: 'ALERT',
        details: {
          username,
          targetUser: user.id,
          message: 'Multiple failed login attempts detected'
        },
        ipAddress: ipAddress || '0.0.0.0',
        userAgent: 'System',
        resourceId: 'login',
        status: 'BLOCKED',
        userId: user.id
      });
      
      // Lock the account temporarily
      const lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
      await User.update(
        { 
          accountLocked: true,
          accountLockedUntil: lockUntil,
          failedLoginAttempts: 0 // Reset counter
        },
        { where: { id: user.id } }
      );
      
      console.log(`🔒 Account locked for user ${username} due to suspicious activity`);
    }
  } catch (error) {
    console.error('Failed to handle failed login:', error);
  }
};

module.exports = {
  logAccessMiddleware,
  authEventLogger,
  otpEventLogger
};