// middlewares/security.js - Enhanced security middleware
const crypto = require('crypto');
const { logActivity } = require('../services/loggerService');

// CSRF Protection middleware
const csrfProtection = (req, res, next) => {
  // Skip CSRF for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  const token = req.headers['x-csrf-token'] || req.body._csrf;
  const sessionToken = req.session?.csrfToken;
  
  if (!token || !sessionToken || token !== sessionToken) {
    console.warn('🚨 CSRF token validation failed:', {
      ip: req.ip,
      method: req.method,
      path: req.path,
      providedToken: token ? 'present' : 'missing',
      sessionToken: sessionToken ? 'present' : 'missing'
    });
    
    return res.status(403).json({
      success: false,
      message: 'Invalid CSRF token'
    });
  }
  
  next();
};

// SQL Injection detection middleware
const sqlInjectionProtection = (req, res, next) => {
  const suspiciousPatterns = [
    /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)/gi,
    /(\b(or|and)\s+\d+\s*=\s*\d+)/gi,
    /('|\"|;|--|#|\*|\/\*|\*\/)/gi,
    /(\)\s*;\s*(drop|delete|truncate))/gi
  ];
  
  const checkValue = (value) => {
    if (typeof value === 'string') {
      return suspiciousPatterns.some(pattern => pattern.test(value));
    }
    return false;
  };
  
  const checkObject = (obj) => {
    for (const key in obj) {
      if (checkValue(key) || checkValue(obj[key])) {
        return true;
      }
      if (typeof obj[key] === 'object' && obj[key] !== null) {
        if (checkObject(obj[key])) {
          return true;
        }
      }
    }
    return false;
  };
  
  if (checkObject(req.query) || checkObject(req.body) || checkObject(req.params)) {
    console.warn('🚨 Potential SQL injection attempt detected:', {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      query: req.query,
      body: req.body,
      params: req.params
    });
    
    logActivity({
      action: 'SQL_INJECTION_ATTEMPT',
      category: 'SECURITY',
      severity: 'ALERT',
      details: {
        query: req.query,
        body: req.body,
        params: req.params
      },
      ipAddress: req.ip,
      userAgent: req.get('user-agent') || 'Unknown',
      resourceId: req.originalUrl,
      status: 'BLOCKED'
    });
    
    return res.status(400).json({
      success: false,
      message: 'Invalid request data detected'
    });
  }
  
  next();
};

// XSS Protection middleware
const xssProtection = (req, res, next) => {
  const xssPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<iframe[^>]*>/gi,
    /<object[^>]*>/gi,
    /<embed[^>]*>/gi,
    /<meta[^>]*>/gi,
    /<link[^>]*>/gi,
    /expression\s*\(/gi,
    /vbscript:/gi,
    /<svg[^>]*>/gi
  ];
  
  const checkValue = (value) => {
    if (typeof value === 'string') {
      return xssPatterns.some(pattern => pattern.test(value));
    }
    return false;
  };
  
  const checkObject = (obj) => {
    for (const key in obj) {
      if (checkValue(key) || checkValue(obj[key])) {
        return true;
      }
      if (typeof obj[key] === 'object' && obj[key] !== null) {
        if (checkObject(obj[key])) {
          return true;
        }
      }
    }
    return false;
  };
  
  if (checkObject(req.body) || checkObject(req.query)) {
    console.warn('🚨 Potential XSS attempt detected:', {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      body: req.body,
      query: req.query
    });
    
    logActivity({
      action: 'XSS_ATTEMPT',
      category: 'SECURITY',
      severity: 'ALERT',
      details: {
        body: req.body,
        query: req.query
      },
      ipAddress: req.ip,
      userAgent: req.get('user-agent') || 'Unknown',
      resourceId: req.originalUrl,
      status: 'BLOCKED'
    });
    
    return res.status(400).json({
      success: false,
      message: 'Invalid content detected in request'
    });
  }
  
  next();
};

// Request size limiting middleware
const requestSizeLimit = (maxSize = 1024 * 1024) => { // Default 1MB
  return (req, res, next) => {
    let size = 0;
    
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxSize) {
        console.warn('🚨 Request size limit exceeded:', {
          ip: req.ip,
          size,
          maxSize,
          path: req.path
        });
        
        res.status(413).json({
          success: false,
          message: 'Request entity too large'
        });
      }
    });
    
    next();
  };
};

// Suspicious activity detection middleware
const suspiciousActivityMonitor = (req, res, next) => {
  // Track requests per IP in memory (for demo - use Redis in production)
  if (!global.requestTracker) {
    global.requestTracker = new Map();
  }
  
  const ip = req.ip;
  const now = Date.now();
  const timeWindow = 60 * 1000; // 1 minute
  
  if (!global.requestTracker.has(ip)) {
    global.requestTracker.set(ip, []);
  }
  
  const requests = global.requestTracker.get(ip);
  
  // Remove old requests
  while (requests.length > 0 && requests[0] < now - timeWindow) {
    requests.shift();
  }
  
  requests.push(now);
  
  // Check for unusual patterns
  const requestCount = requests.length;
  const uniquePaths = new Set();
  
  if (requestCount > 50) { // More than 50 requests per minute
    console.warn('🚨 Suspicious activity detected - high request rate:', {
      ip,
      requestCount,
      timeWindow: '1 minute'
    });
    
    logActivity({
      action: 'SUSPICIOUS_REQUEST_RATE',
      category: 'SECURITY',
      severity: 'WARNING',
      details: {
        requestCount,
        timeWindow: '1 minute'
      },
      ipAddress: ip,
      userAgent: req.get('user-agent') || 'Unknown',
      resourceId: req.originalUrl,
      status: 'MONITORED'
    });
  }
  
  next();
};

// Content Security Policy headers
const securityHeaders = (req, res, next) => {
  // HSTS
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  
  // XSS Protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // No Sniff
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Frame Options
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Content Security Policy
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https:; " +
    "connect-src 'self'; " +
    "font-src 'self'; " +
    "object-src 'none'; " +
    "media-src 'self'; " +
    "frame-src 'none';"
  );
  
  // Remove server information
  res.removeHeader('X-Powered-By');
  
  next();
};

// Request fingerprinting for bot detection
const requestFingerprinting = (req, res, next) => {
  const fingerprint = {
    userAgent: req.get('user-agent'),
    acceptLanguage: req.get('accept-language'),
    acceptEncoding: req.get('accept-encoding'),
    connection: req.get('connection'),
    ip: req.ip
  };
  
  // Simple bot detection patterns
  const botPatterns = [
    /bot|crawler|spider|automated|script/gi,
    /postman|curl|wget|axios/gi
  ];
  
  const userAgent = fingerprint.userAgent || '';
  const isBot = botPatterns.some(pattern => pattern.test(userAgent));
  
  if (isBot && req.path.startsWith('/api/auth/')) {
    console.warn('🤖 Bot detected accessing auth endpoints:', {
      fingerprint,
      path: req.path
    });
    
    logActivity({
      action: 'BOT_DETECTED',
      category: 'SECURITY',
      severity: 'INFO',
      details: {
        fingerprint,
        path: req.path
      },
      ipAddress: req.ip,
      userAgent: userAgent,
      resourceId: req.originalUrl,
      status: 'MONITORED'
    });
  }
  
  req.fingerprint = fingerprint;
  next();
};

module.exports = {
  csrfProtection,
  sqlInjectionProtection,
  xssProtection,
  requestSizeLimit,
  suspiciousActivityMonitor,
  securityHeaders,
  requestFingerprinting
};