/**
 * Centralized Error Handler Middleware
 * Handles all errors in a consistent way across the application
 */

const { AppError } = require('../errors');
const { logActivity } = require('../services/loggerService');

/**
 * Async error wrapper
 * Catches errors in async route handlers
 */
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

/**
 * Error type validator
 * Checks if error is operational (expected) or programming error
 */
const isOperationalError = (error) => {
  if (error instanceof AppError) {
    return error.isOperational;
  }
  return false;
};

/**
 * Error logger
 * Logs error details with appropriate severity
 */
const logError = async (error, req) => {
  try {
    const severity = error.statusCode >= 500 ? 'ERROR' : 'WARNING';
    
    await logActivity({
      action: 'APPLICATION_ERROR',
      category: 'SYSTEM',
      severity,
      details: {
        errorType: error.constructor.name,
        errorCode: error.errorCode || 'UNKNOWN',
        message: error.message,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
        path: req.originalUrl,
        method: req.method,
        query: req.query,
        params: req.params,
        ip: req.ip,
        userAgent: req.get('user-agent')
      },
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('user-agent') || 'Unknown',
      resourceId: req.originalUrl,
      status: 'ERROR',
      userId: req.user ? req.user.id : null
    });
  } catch (logError) {
    console.error('Failed to log error:', logError);
  }
};

/**
 * Error response sender
 * Formats and sends error response
 */
const sendErrorResponse = (error, req, res) => {
  // Set default values
  error.statusCode = error.statusCode || 500;
  error.errorCode = error.errorCode || 'INTERNAL_ERROR';
  
  // Log error
  console.error(`❌ ${error.errorCode}: ${error.message}`);
  if (process.env.NODE_ENV === 'development') {
    console.error(error.stack);
  }
  
  // Send response
  if (error instanceof AppError) {
    res.status(error.statusCode).json(error.toJSON());
  } else {
    // Generic error response for non-AppError instances
    res.status(error.statusCode).json({
      success: false,
      error: {
        code: error.errorCode,
        message: process.env.NODE_ENV === 'production' 
          ? 'An error occurred' 
          : error.message,
        ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
      }
    });
  }
};

/**
 * Main error handler middleware
 */
const errorHandler = async (error, req, res, next) => {
  // Clone error to avoid modifying the original
  let err = Object.assign({}, error);
  err.message = error.message;
  err.stack = error.stack;
  
  // Handle specific error types
  
  // Sequelize validation errors
  if (error.name === 'SequelizeValidationError') {
    const errors = error.errors.map(e => ({
      field: e.path,
      message: e.message
    }));
    err = new AppError('Validation failed', 400, 'VALIDATION_ERROR', { errors });
  }
  
  // Sequelize unique constraint errors
  if (error.name === 'SequelizeUniqueConstraintError') {
    const field = Object.keys(error.fields)[0];
    err = new AppError(`${field} already exists`, 409, 'DUPLICATE_ERROR', { field });
  }
  
  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    err = new AppError('Invalid token', 401, 'TOKEN_INVALID');
  }
  
  if (error.name === 'TokenExpiredError') {
    err = new AppError('Token expired', 401, 'TOKEN_EXPIRED');
  }
  
  // MongoDB CastError
  if (error.name === 'CastError') {
    err = new AppError(`Invalid ${error.path}: ${error.value}`, 400, 'INVALID_ID');
  }
  
  // Multer file upload errors
  if (error.code === 'LIMIT_FILE_SIZE') {
    err = new AppError('File too large', 400, 'FILE_TOO_LARGE');
  }
  
  // Log error
  await logError(err, req);
  
  // Send error response
  sendErrorResponse(err, req, res);
};

/**
 * 404 Not Found handler
 */
const notFoundHandler = (req, res, next) => {
  const error = new AppError(`Path not found: ${req.originalUrl}`, 404, 'NOT_FOUND');
  next(error);
};

/**
 * Unhandled rejection handler
 */
const unhandledRejectionHandler = (reason, promise) => {
  console.error('🚨 Unhandled Promise Rejection:');
  console.error(reason);
  
  // Log critical error
  logActivity({
    action: 'UNHANDLED_REJECTION',
    category: 'SYSTEM',
    severity: 'ERROR',
    details: {
      reason: reason.toString(),
      stack: reason.stack
    },
    ipAddress: '127.0.0.1',
    userAgent: 'System',
    resourceId: 'system',
    status: 'ERROR'
  }).catch(console.error);
  
  // In production, you might want to gracefully shutdown
  if (process.env.NODE_ENV === 'production') {
    console.error('Shutting down application due to unhandled rejection...');
    process.exit(1);
  }
};

/**
 * Uncaught exception handler
 */
const uncaughtExceptionHandler = (error) => {
  console.error('🚨 Uncaught Exception:');
  console.error(error);
  
  // Log critical error
  logActivity({
    action: 'UNCAUGHT_EXCEPTION',
    category: 'SYSTEM',
    severity: 'ERROR',
    details: {
      message: error.message,
      stack: error.stack
    },
    ipAddress: '127.0.0.1',
    userAgent: 'System',
    resourceId: 'system',
    status: 'ERROR'
  }).catch(console.error);
  
  // Always shutdown on uncaught exceptions
  console.error('Shutting down application due to uncaught exception...');
  process.exit(1);
};

// Install global error handlers
process.on('unhandledRejection', unhandledRejectionHandler);
process.on('uncaughtException', uncaughtExceptionHandler);

module.exports = {
  errorHandler,
  notFoundHandler,
  asyncHandler,
  isOperationalError,
  logError,
  sendErrorResponse
};