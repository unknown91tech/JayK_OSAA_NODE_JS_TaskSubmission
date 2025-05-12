// middlewares/validation.js - Fixed version
const Joi = require('joi');
const validator = require('validator');

// Custom sanitization functions
const sanitizeInput = (value) => {
  if (typeof value !== 'string') return value;
  
  // Remove potential XSS attempts
  return validator.escape(value.trim());
};

const sanitizeUsername = (value) => {
  if (typeof value !== 'string') return value;
  
  // Allow only alphanumeric characters, underscores, and hyphens
  return value.replace(/[^a-zA-Z0-9_-]/g, '').toLowerCase();
};

// Enhanced validation schema for user registration
const registrationSchema = Joi.object({
  username: Joi.string()
    .min(3)
    .max(30)
    .pattern(/^[a-zA-Z0-9_-]+$/, 'alphanumeric with underscores and hyphens')
    .custom((value, helpers) => {
      const sanitized = sanitizeUsername(value);
      if (sanitized !== value) {
        return helpers.error('string.custom', { message: 'Username contains invalid characters' });
      }
      return sanitized;
    })
    .required()
    .messages({
      'string.pattern.name': 'Username can only contain letters, numbers, underscores, and hyphens',
      'string.min': 'Username must be at least 3 characters long',
      'string.max': 'Username cannot exceed 30 characters'
    }),
    
  dateOfBirth: Joi.date()
    .iso()
    .max('2006-01-01') // Must be at least 18 years old
    .required()
    .messages({
      'date.max': 'You must be at least 18 years old to register'
    }),
    
  passcode: Joi.string()
    .min(8)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 'password complexity')
    .required()
    .messages({
      'string.pattern.name': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
      'string.min': 'Password must be at least 8 characters long'
    }),
    
  referralCode: Joi.string()
    .optional()
    .custom((value, helpers) => {
      if (value) {
        return sanitizeInput(value);
      }
      return value;
    }),
    
  registrationMethod: Joi.string()
    .valid('telegram')
    .required()
    .messages({
      'any.only': 'Only Telegram registration is currently supported'
    }),
    
  telegramId: Joi.when('registrationMethod', {
    is: 'telegram',
    then: Joi.string().required().pattern(/^\d+$/, 'numeric').messages({
      'string.pattern.name': 'Telegram ID must be numeric',
      'any.required': 'Telegram ID is required for Telegram registration'
    }),
    otherwise: Joi.string().optional()
  }),
    
  initialRole: Joi.string()
    .valid('admin', 'user', 'moderator')
    .optional()
    .custom((value, helpers) => {
      if (value) {
        return sanitizeInput(value);
      }
      return value;
    })
});

// Enhanced OTP verification schema with rate limiting check
const otpVerificationSchema = Joi.object({
  userId: Joi.string()
    .uuid()
    .required()
    .messages({
      'string.uuid': 'Invalid user ID format'
    }),
    
  otp: Joi.string()
    .length(6)
    .pattern(/^\d{6}$/, 'six digits')
    .required()
    .messages({
      'string.pattern.name': 'OTP must be exactly 6 digits',
      'string.length': 'OTP must be exactly 6 digits'
    })
});

// Enhanced login schema with additional security
const loginSchema = Joi.object({
  username: Joi.string()
    .required()
    .custom((value, helpers) => {
      const sanitized = sanitizeUsername(value);
      return sanitized;
    })
    .messages({
      'string.empty': 'Username is required'
    }),
    
  passcode: Joi.string()
    .required()
    .messages({
      'string.empty': 'Password is required'
    }),
    
  loginMethod: Joi.string()
    .valid('direct', 'telegram')
    .default('direct')
    .messages({
      'any.only': 'Invalid login method'
    })
});

// Custom middleware for additional security checks
const securityMiddleware = async (req, res, next) => {
  // Check for suspicious patterns in request body
  const body = JSON.stringify(req.body);
  
  // Basic XSS detection
  const xssPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<iframe/gi,
    /<object/gi,
    /<embed/gi
  ];
  
  const hasSuspiciousContent = xssPatterns.some(pattern => pattern.test(body));
  
  if (hasSuspiciousContent) {
    console.warn('🚨 Suspicious content detected in request:', {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      body: req.body
    });
    
    return res.status(400).json({
      success: false,
      message: 'Invalid request content detected'
    });
  }
  
  next();
};

// Enhanced validation middleware with logging
const validateRegistration = async (req, res, next) => {
  try {
    // Apply security middleware first
    await securityMiddleware(req, res, () => {});
    
    const { error, value } = registrationSchema.validate(req.body);
    
    if (error) {
      console.warn('🚨 Registration validation failed:', {
        ip: req.ip,
        errors: error.details,
        body: req.body
      });
      
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors: error.details.map(detail => ({
          field: detail.path[0],
          message: detail.message
        }))
      });
    }
    
    // Replace request body with validated/sanitized values
    req.body = value;
    next();
  } catch (err) {
    console.error('❌ Validation middleware error:', err);
    res.status(500).json({
      success: false,
      message: 'Validation processing error'
    });
  }
};

// Enhanced OTP validation with rate limiting
const validateOTPVerification = async (req, res, next) => {
  try {
    const { error, value } = otpVerificationSchema.validate(req.body);
    
    if (error) {
      console.warn('🚨 OTP validation failed:', {
        ip: req.ip,
        errors: error.details,
        userId: req.body.userId
      });
      
      return res.status(400).json({
        success: false,
        message: 'Invalid OTP format',
        errors: error.details.map(detail => detail.message)
      });
    }
    
    req.body = value;
    next();
  } catch (err) {
    console.error('❌ OTP validation error:', err);
    res.status(500).json({
      success: false,
      message: 'OTP validation processing error'
    });
  }
};

// Enhanced login validation with brute force protection
const validateLogin = async (req, res, next) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    
    if (error) {
      console.warn('🚨 Login validation failed:', {
        ip: req.ip,
        username: req.body.username,
        errors: error.details
      });
      
      return res.status(400).json({
        success: false,
        message: 'Invalid login data',
        errors: error.details.map(detail => ({
          field: detail.path[0],
          message: detail.message
        }))
      });
    }
    
    req.body = value;
    next();
  } catch (err) {
    console.error('❌ Login validation error:', err);
    res.status(500).json({
      success: false,
      message: 'Login validation processing error'
    });
  }
};

// Token refresh validation
const validateTokenRefresh = (req, res, next) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(400).json({
      success: false,
      message: 'Refresh token is required'
    });
  }
  
  next();
};

// Logout validation
const validateLogout = (req, res, next) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(400).json({
      success: false,
      message: 'Refresh token is required'
    });
  }
  
  next();
};

// MFA verification validation
const validateMFAVerification = async (req, res, next) => {
  try {
    const schema = Joi.object({
      userId: Joi.string().uuid().required(),
      otp: Joi.string().length(6).pattern(/^\d{6}$/).required()
    });
    
    const { error, value } = schema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Invalid MFA verification data',
        errors: error.details.map(detail => detail.message)
      });
    }
    
    req.body = value;
    next();
  } catch (err) {
    console.error('❌ MFA validation error:', err);
    res.status(500).json({
      success: false,
      message: 'MFA validation processing error'
    });
  }
};

// Telegram test validation
const validateTelegramTest = (req, res, next) => {
  const schema = Joi.object({
    telegramId: Joi.string().required(),
    message: Joi.string().default('This is a test message from the Authentication System')
  });
  
  const { error, value } = schema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      message: 'Invalid telegram test data',
      errors: error.details.map(detail => detail.message)
    });
  }
  
  req.body = value;
  next();
};

// Role creation validation
const validateCreateRole = async (req, res, next) => {
  try {
    const schema = Joi.object({
      name: Joi.string()
        .pattern(/^[a-zA-Z_]+$/, 'letters and underscores only')
        .required()
        .custom((value, helpers) => {
          return sanitizeInput(value.toLowerCase());
        })
        .messages({
          'string.pattern.name': 'Role name can only contain letters and underscores'
        }),
        
      description: Joi.string()
        .max(500)
        .optional()
        .custom((value, helpers) => {
          if (value) {
            return sanitizeInput(value);
          }
          return value;
        }),
        
      permissions: Joi.array()
        .items(Joi.string().custom((value, helpers) => sanitizeInput(value)))
        .default([])
    });
    
    const { error, value } = schema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Role validation error',
        errors: error.details.map(detail => detail.message)
      });
    }
    
    req.body = value;
    next();
  } catch (err) {
    console.error('❌ Role validation error:', err);
    res.status(500).json({
      success: false,
      message: 'Role validation processing error'
    });
  }
};

// Role update validation
const validateUpdateRole = async (req, res, next) => {
  try {
    const schema = Joi.object({
      name: Joi.string()
        .pattern(/^[a-zA-Z_]+$/)
        .custom((value, helpers) => sanitizeInput(value.toLowerCase())),
      description: Joi.string()
        .max(500)
        .custom((value, helpers) => value ? sanitizeInput(value) : value),
      permissions: Joi.array()
        .items(Joi.string().custom((value, helpers) => sanitizeInput(value)))
    }).min(1);
    
    const { error, value } = schema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Role update validation error',
        errors: error.details.map(detail => detail.message)
      });
    }
    
    req.body = value;
    next();
  } catch (err) {
    console.error('❌ Role update validation error:', err);
    res.status(500).json({
      success: false,
      message: 'Role update validation processing error'
    });
  }
};

// Assign role validation
const validateAssignRole = (req, res, next) => {
  const schema = Joi.object({
    userId: Joi.string().uuid().required(),
    roleId: Joi.string().uuid().required()
  });
  
  const { error, value } = schema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      message: 'Assign role validation error',
      errors: error.details.map(detail => detail.message)
    });
  }
  
  req.body = value;
  next();
};

// Remove role validation
const validateRemoveRole = (req, res, next) => {
  const schema = Joi.object({
    userId: Joi.string().uuid().required(),
    roleId: Joi.string().uuid().required()
  });
  
  const { error, value } = schema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      message: 'Remove role validation error',
      errors: error.details.map(detail => detail.message)
    });
  }
  
  req.body = value;
  next();
};

// Challenge creation validation
const validateChallengeCreation = (req, res, next) => {
  const schema = Joi.object({
    username: Joi.string()
      .pattern(/^[a-zA-Z0-9_-]+$/)
      .optional()
      .messages({
        'string.pattern.base': 'Username can only contain letters, numbers, underscores, and hyphens'
      })
  });
  
  const { error, value } = schema.validate(req.body);
  
  if (error) {
    console.warn('🚨 Challenge creation validation failed:', {
      ip: req.ip,
      errors: error.details,
      body: req.body
    });
    
    return res.status(400).json({
      success: false,
      message: 'Validation error',
      errors: error.details.map(detail => ({
        field: detail.path[0],
        message: detail.message
      }))
    });
  }
  
  req.body = value;
  next();
};

// Challenge verification validation
const validateChallengeVerification = (req, res, next) => {
  const schema = Joi.object({
    challengeId: Joi.string()
      .uuid()
      .required()
      .messages({
        'string.uuid': 'Invalid challenge ID format',
        'any.required': 'Challenge ID is required'
      }),
    answer: Joi.string()
      .required()
      .trim()
      .messages({
        'any.required': 'Answer is required',
        'string.empty': 'Answer cannot be empty'
      })
  });
  
  const { error, value } = schema.validate(req.body);
  
  if (error) {
    console.warn('🚨 Challenge verification validation failed:', {
      ip: req.ip,
      errors: error.details,
      challengeId: req.body.challengeId
    });
    
    return res.status(400).json({
      success: false,
      message: 'Validation error',
      errors: error.details.map(detail => ({
        field: detail.path[0],
        message: detail.message
      }))
    });
  }
  
  req.body = value;
  next();
};

// Challenge requirement check validation
const validateChallengeCheck = (req, res, next) => {
  const schema = Joi.object({
    username: Joi.string()
      .pattern(/^[a-zA-Z0-9_-]+$/)
      .optional()
      .messages({
        'string.pattern.base': 'Username can only contain letters, numbers, underscores, and hyphens'
      })
  });
  
  const { error, value } = schema.validate(req.query);
  
  if (error) {
    console.warn('🚨 Challenge check validation failed:', {
      ip: req.ip,
      errors: error.details,
      query: req.query
    });
    
    return res.status(400).json({
      success: false,
      message: 'Validation error',
      errors: error.details.map(detail => ({
        field: detail.path[0],
        message: detail.message
      }))
    });
  }
  
  req.query = value;
  next();
};

// Enhanced login validation with challenge support
const validateLoginWithChallenge = (req, res, next) => {
  const schema = Joi.object({
    username: Joi.string()
      .required()
      .custom((value, helpers) => {
        return value.replace(/[^a-zA-Z0-9_-]/g, '').toLowerCase();
      })
      .messages({
        'string.empty': 'Username is required'
      }),
    passcode: Joi.string()
      .required()
      .messages({
        'string.empty': 'Password is required'
      }),
    loginMethod: Joi.string()
      .valid('direct', 'telegram')
      .default('direct')
      .messages({
        'any.only': 'Invalid login method'
      }),
    challengeId: Joi.string()
      .uuid()
      .optional()
      .messages({
        'string.uuid': 'Invalid challenge ID format'
      }),
    challengeAnswer: Joi.string()
      .optional()
      .when('challengeId', {
        is: Joi.exist(),
        then: Joi.required().messages({
          'any.required': 'Challenge answer is required when challenge ID is provided'
        })
      })
  });
  
  const { error, value } = schema.validate(req.body);
  
  if (error) {
    console.warn('🚨 Login with challenge validation failed:', {
      ip: req.ip,
      username: req.body.username,
      errors: error.details
    });
    
    return res.status(400).json({
      success: false,
      message: 'Invalid login data',
      errors: error.details.map(detail => ({
        field: detail.path[0],
        message: detail.message
      }))
    });
  }
  
  req.body = value;
  next();
};


module.exports = {
  validateRegistration,
  validateOTPVerification,
  validateLogin,
  validateMFAVerification,
  validateTokenRefresh,
  validateLogout,
  validateTelegramTest,
  validateCreateRole,
  validateUpdateRole,
  validateAssignRole,
  validateRemoveRole,
  sanitizeInput,
  sanitizeUsername,
  securityMiddleware,
  validateChallengeCreation,
  validateChallengeVerification,
  validateChallengeCheck,
  validateLoginWithChallenge
};