// app.js - Enhanced with graceful database handling
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const session = require('express-session');
const SequelizeStore = require('connect-session-sequelize')(session.Store);
const crypto = require('crypto');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const swaggerDocument = YAML.load('./docs/swagger.yaml');



// Route imports
const authRoutes = require('./routes/authRoutes');
const roleRoutes = require('./routes/roleRoutes');
const logRoutes = require('./routes/logRoutes');

// Service imports
const { initTelegramBot } = require('./services/telegramService');
const { initLogging } = require('./services/loggerService');
const { scheduleTokenCleanup } = require('./schedulers/tokenCleanup');
const { 
  initializeModels, 
  checkDatabaseHealth, 
  migrateExistingData 
} = require('./models');
const { sequelize } = require('./config/db');

// Security middleware imports
const { apiLimiter } = require('./middlewares/rateLimiter');
const { logAccessMiddleware } = require('./middlewares/logging');
const {
  securityHeaders,
  requestSizeLimit,
  suspiciousActivityMonitor
} = require('./middlewares/security');

require('dotenv').config();

// Initialize Express app
const app = express();

// Application initialization function
const initializeApplication = async () => {
  try {
    console.log('🚀 Starting Secure Authentication System...');
    
    // 1. Initialize database models and associations
    console.log('📦 Initializing models...');
    const modelsInitialized = await initializeModels();
    if (!modelsInitialized) {
      throw new Error('Failed to initialize models');
    }
    
    // 2. Check database health
    console.log('🏥 Checking database health...');
    const healthCheck = await checkDatabaseHealth();
    if (!healthCheck) {
      console.warn('⚠️  Database health check had issues, but continuing...');
    }
    
    // 3. Handle data migrations if needed
    console.log('🔄 Checking for data migrations...');
    const migrationCheck = await migrateExistingData();
    if (!migrationCheck) {
      console.warn('⚠️  Data migration had issues, but continuing...');
    }
    
    return true;
  } catch (error) {
    console.error('❌ Application initialization failed:', error);
    return false;
  }
};

// Initialize models at startup
let initializationPromise = null;

const getInitializationPromise = () => {
  if (!initializationPromise) {
    initializationPromise = initializeApplication();
  }
  return initializationPromise;
};

// Middleware to ensure initialization before processing requests
const ensureInitialized = async (req, res, next) => {
  try {
    const initialized = await getInitializationPromise();
    if (!initialized) {
      return res.status(503).json({
        success: false,
        message: 'System is initializing, please try again in a moment'
      });
    }
    next();
  } catch (error) {
    console.error('Initialization check failed:', error);
    res.status(503).json({
      success: false,
      message: 'System initialization error'
    });
  }
};

// Security headers (using enhanced security middleware)
app.use(securityHeaders);

// Helmet configuration for additional security
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS configuration with security considerations
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn('🚨 CORS blocked request from:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
};

app.use(cors(corsOptions));

// Compression middleware
app.use(compression());

// Request size limiting
app.use(requestSizeLimit(process.env.MAX_REQUEST_SIZE || 1024 * 1024)); // 1MB default

// Body parsing middleware with limits
app.use(express.json({ 
  limit: '1mb',
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));
app.use(express.urlencoded({ 
  extended: true, 
  limit: '1mb' 
}));

// Session configuration for CSRF protection
const sessionStore = new SequelizeStore({
  db: sequelize,
  checkExpirationInterval: 15 * 60 * 1000, // Check every 15 minutes
  expiration: 24 * 60 * 60 * 1000 // 24 hours
});

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS in production
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict'
  },
  name: 'auth.session' // Change default session name
}));

// Generate CSRF token for each session
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
});

// Apply general rate limiting to all API routes
app.use('/api', apiLimiter);

// Apply logging middleware to all routes
app.use(logAccessMiddleware);

// Apply suspicious activity monitoring
app.use(suspiciousActivityMonitor);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Initialize services asynchronously
const initializeServices = async () => {
  try {
    console.log('🚀 Starting application services...');
    
    // Initialize Telegram bot
    initTelegramBot().then(initialized => {
      if (initialized) {
        console.log('✅ Telegram bot initialized successfully');
      } else {
        console.warn('⚠️  Telegram bot initialization had issues');
      }
    }).catch(err => {
      console.error('❌ Failed to initialize Telegram bot:', err);
    });
    
    // Initialize logging system
    initLogging().then(initialized => {
      if (initialized) {
        console.log('✅ Logging system initialized successfully');
      } else {
        console.warn('⚠️  Logging system initialization had issues');
      }
    }).catch(err => {
      console.error('❌ Failed to initialize logging system:', err);
    });
    
    // Create session table if it doesn't exist
    sessionStore.sync().catch(err => {
      console.error('❌ Failed to sync session store:', err);
    });
    
    // Schedule token cleanup (if not in test environment)
    if (process.env.NODE_ENV !== 'test') {
      scheduleTokenCleanup();
    }
    
    console.log('✅ Application services initialization completed');
  } catch (error) {
    console.error('❌ Service initialization error:', error);
  }
};

// Start service initialization
initializeServices();

// Health check endpoint (excluded from rate limiting and initialization check)
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

// CSRF token endpoint
app.get('/api/csrf-token', ensureInitialized, (req, res) => {
  res.json({ csrfToken: req.session.csrfToken });
});

// Routes with initialization check
app.use('/api/auth', ensureInitialized, authRoutes);
app.use('/api/roles', ensureInitialized, roleRoutes);
app.use('/api/logs', ensureInitialized, logRoutes);

// API documentation route
app.get('/', ensureInitialized, (req, res) => {
  res.json({ 
    message: 'Authentication API is running',
    version: '1.0.0',
    status: 'operational',
    features: [
      'Graceful Database Handling',
      'Existing Data Preservation',
      'Automatic Schema Migration',
      'Robust Rate Limiting',
      'Multi-layer Security',
      'Comprehensive Logging'
    ],
    endpoints: {
      // Security
      health: '/health',
      csrfToken: '/api/csrf-token',
      
      // User Authentication
      register: '/api/auth/register',
      verifyOtp: '/api/auth/verify-otp',
      login: '/api/auth/login',
      verifyMfa: '/api/auth/verify-mfa',
      
      // Token Management
      refreshToken: '/api/auth/refresh-token',
      logout: '/api/auth/logout',
      logoutAll: '/api/auth/logout-all',
      sessions: '/api/auth/sessions',
      terminateSession: '/api/auth/sessions/:sessionId',
      
      // MFA Settings
      toggleMfa: '/api/auth/toggle-mfa',

      // Role Management (Admin)
      roles: '/api/roles',
      roleById: '/api/roles/:id',
      assignRole: '/api/roles/assign',
      removeRole: '/api/roles/remove',
      userRoles: '/api/roles/user/:userId',
      roleUsers: '/api/roles/:roleId/users',
      
      // Logging and Monitoring (Admin)
      logs: '/api/logs/activities',
      logMetadata: '/api/logs/metadata',
      userActivity: '/api/logs/user/:userId',
      securityAlerts: '/api/logs/security-alerts',
      verifyLogIntegrity: '/api/logs/verify-integrity',
      rawLogs: '/api/logs/raw/:category/:date',
      loginStats: '/api/logs/login-stats',
      
      // Testing & Admin
      testTelegram: '/api/auth/test-telegram',
      botInfo: '/api/auth/bot-info',
      mfaStats: '/api/auth/mfa-stats'
    } 
  });
});

// 404 handler
app.use((req, res, next) => {
  console.warn('📍 404 - Route not found:', {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('user-agent')
  });
  
  res.status(404).json({
    success: false,
    message: 'Route not found',
    path: req.originalUrl
  });
});

// Enhanced error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err.stack);
  
  // Log the error using our logging service
  const { logActivity } = require('./services/loggerService');
  logActivity({
    action: 'SERVER_ERROR',
    category: 'SYSTEM',
    severity: 'ERROR',
    details: {
      error: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
      path: req.originalUrl,
      method: req.method,
      body: req.body,
      query: req.query
    },
    ipAddress: req.ip || req.connection.remoteAddress,
    userAgent: req.get('user-agent') || 'Unknown',
    resourceId: req.originalUrl,
    status: 'ERROR',
    userId: req.user ? req.user.id : null
  }).catch(logErr => {
    console.error('Failed to log server error:', logErr);
  });
  
  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(500).json({
    success: false,
    message: 'Internal Server Error',
    error: isDevelopment ? err.message : undefined,
    stack: isDevelopment ? err.stack : undefined,
    timestamp: new Date().toISOString()
  });
});

// Graceful shutdown handling
process.on('SIGTERM', async () => {
  console.log('🔄 SIGTERM received, shutting down gracefully...');
  
  try {
    // Close database connection
    await sequelize.close();
    console.log('✅ Database connection closed');
    
    // Close other connections if needed
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during shutdown:', error);
    process.exit(1);
  }
});

module.exports = app;