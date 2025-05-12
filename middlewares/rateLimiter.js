// middlewares/rateLimiter.js - Fixed imports
const rateLimit = require('express-rate-limit');
const { User, LoginAttempt, OtpLog } = require('../models');  // Changed this line
const { Op } = require('sequelize');
const { logActivity } = require('../services/loggerService');

// Store for tracking suspicious IPs
const suspiciousIPs = new Map();

// Enhanced rate limiter for login attempts with dynamic blocking
const loginRateLimiter = async (req, res, next) => {
  try {
    const { username } = req.body;
    const clientIP = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
    
    // Check if IP is blocked
    if (suspiciousIPs.has(clientIP)) {
      const blockInfo = suspiciousIPs.get(clientIP);
      if (new Date() < blockInfo.blockedUntil) {
        console.log(`🚫 Blocked IP attempting login: ${clientIP}`);
        
        await logActivity({
          action: 'BLOCKED_IP_LOGIN_ATTEMPT',
          category: 'SECURITY',
          severity: 'ALERT',
          details: {
            username,
            reason: 'IP blocked due to excessive failed attempts',
            blockedUntil: blockInfo.blockedUntil
          },
          ipAddress: clientIP,
          userAgent: req.get('user-agent') || 'Unknown',
          resourceId: '/api/auth/login',
          status: 'BLOCKED'
        });
        
        return res.status(429).json({
          success: false,
          message: 'Too many failed login attempts. IP temporarily blocked.',
          blockedUntil: blockInfo.blockedUntil
        });
      } else {
        // Unblock IP if time has passed
        suspiciousIPs.delete(clientIP);
      }
    }
    
    // Check for user-specific rate limiting
    if (username) {
      const user = await User.findOne({ where: { username } });
      
      if (user) {
        // Check failed attempts in the last hour
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        
        const failedAttempts = await LoginAttempt.count({
          where: {
            userId: user.id,
            successful: false,
            createdAt: {
              [Op.gte]: oneHourAgo
            }
          }
        });
        
        console.log(`🔒 User ${username} has ${failedAttempts} failed login attempts in the last hour`);
        
        // Graduated blocking: 5 attempts = 15 min block, 10 attempts = 1 hour block
        if (failedAttempts >= 10) {
          const lockUntil = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
          await User.update(
            { 
              accountLocked: true,
              accountLockedUntil: lockUntil,
              failedLoginAttempts: failedAttempts
            },
            { where: { id: user.id } }
          );
          
          await logActivity({
            action: 'ACCOUNT_LOCKED',
            category: 'SECURITY',
            severity: 'ALERT',
            details: {
              username,
              reason: 'Excessive failed login attempts',
              failedAttempts,
              lockDuration: '1 hour'
            },
            ipAddress: clientIP,
            userAgent: req.get('user-agent') || 'Unknown',
            resourceId: '/api/auth/login',
            status: 'BLOCKED',
            userId: user.id
          });
          
          return res.status(429).json({
            success: false,
            message: 'Account temporarily locked due to too many failed attempts. Try again in 1 hour.'
          });
        } else if (failedAttempts >= 5) {
          return res.status(429).json({
            success: false,
            message: 'Too many failed login attempts. Please try again later.',
            remainingAttempts: 10 - failedAttempts
          });
        }
      }
    }
    
    // Check IP-based rate limiting
    const ipAttempts = await LoginAttempt.count({
      where: {
        ipAddress: clientIP,
        createdAt: {
          [Op.gte]: new Date(Date.now() - 15 * 60 * 1000) // Last 15 minutes
        }
      }
    });
    
    if (ipAttempts >= 20) {
      // Block IP for 30 minutes
      const blockUntil = new Date(Date.now() + 30 * 60 * 1000);
      suspiciousIPs.set(clientIP, { blockedUntil: blockUntil });
      
      await logActivity({
        action: 'IP_BLOCKED',
        category: 'SECURITY',
        severity: 'ALERT',
        details: {
          reason: 'Excessive login attempts from IP',
          attemptCount: ipAttempts,
          blockDuration: '30 minutes'
        },
        ipAddress: clientIP,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: '/api/auth/login',
        status: 'BLOCKED'
      });
      
      return res.status(429).json({
        success: false,
        message: 'Too many login attempts from this IP. Blocked for 30 minutes.'
      });
    }
    
    next();
  } catch (error) {
    console.error('❌ Rate limiter error:', error);
    next(error);
  }
};

// Enhanced OTP rate limiter with user-specific tracking
const otpRateLimiter = async (req, res, next) => {
  try {
    const { userId } = req.body;
    const clientIP = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
    
    if (!userId) {
      return next();
    }
    
    // Check OTP requests in the last 15 minutes
    const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
    
    const otpCount = await OtpLog.count({
      where: {
        userId,
        createdAt: {
          [Op.gte]: fifteenMinutesAgo
        }
      }
    });
    
    console.log(`🔑 User ${userId} has requested ${otpCount} OTPs in the last 15 minutes`);
    
    if (otpCount >= 5) {
      await logActivity({
        action: 'OTP_RATE_LIMITED',
        category: 'SECURITY',
        severity: 'WARNING',
        details: {
          userId,
          otpCount,
          reason: 'Too many OTP requests'
        },
        ipAddress: clientIP,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: req.originalUrl,
        status: 'BLOCKED',
        userId
      });
      
      return res.status(429).json({
        success: false,
        message: 'Too many OTP requests. Please wait 15 minutes before requesting again.'
      });
    }
    
    next();
  } catch (error) {
    console.error('❌ OTP rate limiter error:', error);
    next(error);
  }
};

// General API rate limiter with enhanced tracking
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests, please try again later.',
    resetTime: new Date(Date.now() + 15 * 60 * 1000).toISOString()
  },
  handler: async (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
    
    await logActivity({
      action: 'API_RATE_LIMITED',
      category: 'SECURITY',
      severity: 'WARNING',
      details: {
        reason: 'API rate limit exceeded',
        limit: 100,
        windowMs: 15 * 60 * 1000
      },
      ipAddress: clientIP,
      userAgent: req.get('user-agent') || 'Unknown',
      resourceId: req.originalUrl,
      status: 'BLOCKED'
    });
    
    res.status(429).json({
      success: false,
      message: 'Too many requests, please try again later.',
      resetTime: new Date(Date.now() + 15 * 60 * 1000).toISOString()
    });
  },
  skip: (req) => {
    // Skip rate limiting for some endpoints like health checks
    const skipPaths = ['/health', '/api/health'];
    return skipPaths.includes(req.path);
  }
});

// Stricter rate limiter for sensitive operations
const strictRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // Only 5 requests per 5 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many sensitive operations. Please wait before trying again.',
    resetTime: new Date(Date.now() + 5 * 60 * 1000).toISOString()
  },
  keyGenerator: (req) => {
    // Use both IP and user ID for stricter control
    return `${req.ip}_${req.user?.id || 'anonymous'}`;
  }
});

// Registration rate limiter
const registrationRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Only 3 registrations per hour per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many registration attempts. Please try again later.',
    resetTime: new Date(Date.now() + 60 * 60 * 1000).toISOString()
  },
  handler: async (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
    
    await logActivity({
      action: 'REGISTRATION_RATE_LIMITED',
      category: 'SECURITY',
      severity: 'WARNING',
      details: {
        reason: 'Registration rate limit exceeded',
        limit: 3,
        windowMs: 60 * 60 * 1000
      },
      ipAddress: clientIP,
      userAgent: req.get('user-agent') || 'Unknown',
      resourceId: '/api/auth/register',
      status: 'BLOCKED'
    });
    
    res.status(429).json({
      success: false,
      message: 'Too many registration attempts. Please try again later.',
      resetTime: new Date(Date.now() + 60 * 60 * 1000).toISOString()
    });
  }
});

module.exports = {
  loginRateLimiter,
  otpRateLimiter,
  apiLimiter,
  strictRateLimiter,
  registrationRateLimiter
};