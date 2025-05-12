/**
 * Custom Application Error Classes
 * Provides structured error handling throughout the application
 */

/**
 * Base Application Error
 * All custom errors should extend this class
 */
class AppError extends Error {
  constructor(message, statusCode = 500, errorCode = 'INTERNAL_ERROR', details = null) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.details = details;
    this.timestamp = new Date().toISOString();
    this.isOperational = true; // Operational errors vs programming errors
    
    // Capture stack trace, excluding constructor call from it
    Error.captureStackTrace(this, this.constructor);
  }
  
  /**
   * Convert error to JSON for API responses
   */
  toJSON() {
    return {
      success: false,
      error: {
        code: this.errorCode,
        message: this.message,
        details: this.details,
        timestamp: this.timestamp
      }
    };
  }
}

/**
 * Validation Error
 * Used when request validation fails
 */
class ValidationError extends AppError {
  constructor(message, details = null) {
    super(message, 400, 'VALIDATION_ERROR', details);
  }
}

/**
 * Authentication Error
 * Used when authentication fails
 */
class AuthenticationError extends AppError {
  constructor(message = 'Authentication failed', details = null) {
    super(message, 401, 'AUTHENTICATION_ERROR', details);
  }
}

/**
 * Authorization Error
 * Used when user lacks required permissions
 */
class AuthorizationError extends AppError {
  constructor(message = 'Access denied', details = null) {
    super(message, 403, 'AUTHORIZATION_ERROR', details);
  }
}

/**
 * Not Found Error
 * Used when requested resource doesn't exist
 */
class NotFoundError extends AppError {
  constructor(resource = 'Resource', details = null) {
    super(`${resource} not found`, 404, 'NOT_FOUND', details);
  }
}

/**
 * Conflict Error
 * Used when there's a conflict with current state
 */
class ConflictError extends AppError {
  constructor(message = 'Resource conflict', details = null) {
    super(message, 409, 'CONFLICT_ERROR', details);
  }
}

/**
 * Rate Limit Error
 * Used when rate limit is exceeded
 */
class RateLimitError extends AppError {
  constructor(message = 'Too many requests', details = null) {
    super(message, 429, 'RATE_LIMIT_ERROR', details);
  }
}

/**
 * Business Logic Error
 * Used for business rule violations
 */
class BusinessLogicError extends AppError {
  constructor(message, details = null) {
    super(message, 422, 'BUSINESS_LOGIC_ERROR', details);
  }
}

/**
 * External Service Error
 * Used when external services fail
 */
class ExternalServiceError extends AppError {
  constructor(service, message = 'External service error', details = null) {
    super(`${service}: ${message}`, 503, 'EXTERNAL_SERVICE_ERROR', { service, ...details });
  }
}

/**
 * Database Error Wrapper
 * Wraps database-specific errors into AppError
 */
class DatabaseError extends AppError {
  constructor(originalError) {
    let message = 'Database operation failed';
    let details = { originalError: originalError.message };
    
    // Parse common database errors
    if (originalError.code === '23505' || originalError.name === 'SequelizeUniqueConstraintError') {
      message = 'Duplicate entry detected';
      details.field = originalError.fields;
    } else if (originalError.code === '23503' || originalError.name === 'SequelizeForeignKeyConstraintError') {
      message = 'Referenced resource not found';
      details.constraint = originalError.constraint;
    }
    
    super(message, 409, 'DATABASE_ERROR', details);
  }
}

/**
 * Token Error
 * Used for JWT token-related errors
 */
class TokenError extends AppError {
  constructor(message = 'Invalid token', details = null) {
    let errorCode = 'TOKEN_ERROR';
    
    // Specific token error codes
    if (message.includes('expired')) {
      errorCode = 'TOKEN_EXPIRED';
    } else if (message.includes('invalid')) {
      errorCode = 'TOKEN_INVALID';
    }
    
    super(message, 401, errorCode, details);
  }
}

/**
 * File Upload Error
 * Used for file upload related errors
 */
class FileUploadError extends AppError {
  constructor(message = 'File upload failed', details = null) {
    super(message, 400, 'FILE_UPLOAD_ERROR', details);
  }
}

module.exports = {
  AppError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  BusinessLogicError,
  ExternalServiceError,
  DatabaseError,
  TokenError,
  FileUploadError
};