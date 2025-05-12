// Add this import at the top of authController.js
const { User, Role, UserRole } = require('../models');
const LoginAttempt = require('../models/LoginAttempt');
const OtpLog = require('../models/OtpLog');
const { createOTP, verifyOTP, requestLoginMFA, checkOTPRateLimit } = require('../services/otpService');
const { sendTestMessage } = require('../services/telegramService');
const { generateTokens } = require('../services/tokenService');
const { logActivity } = require('../services/loggerService'); // Add this line
const { needsChallenge, createChallenge, verifyChallenge } = require('../services/challengeService');


require('dotenv').config();
// Register a new user
const registerUser = async (req, res) => {
  try {
    console.log('📝 Processing registration request:', req.body);
    
    const {
      username,
      dateOfBirth,
      passcode,
      referralCode,
      registrationMethod,
      telegramId,
      whatsappNumber,
      initialRole // Optional initial role (only used by admins)
    } = req.body;

    // Check if user already exists with the same username
    const existingUsername = await User.findOne({ where: { username } });
    if (existingUsername) {
      console.log(`❌ Registration failed: Username ${username} already taken`);
      return res.status(400).json({
        success: false,
        message: 'Username already taken'
      });
    }

    // Check if user already exists with the same telegramId or whatsappNumber
    if (registrationMethod === 'telegram' && telegramId) {
      const existingTelegram = await User.findOne({ where: { telegramId } });
      if (existingTelegram) {
        console.log(`❌ Registration failed: Telegram ID ${telegramId} already registered`);
        return res.status(400).json({
          success: false,
          message: 'User already registered with this Telegram account'
        });
      }
    } else if (registrationMethod === 'whatsapp' && whatsappNumber) {
      const existingWhatsapp = await User.findOne({ where: { whatsappNumber } });
      if (existingWhatsapp) {
        console.log(`❌ Registration failed: WhatsApp number ${whatsappNumber} already registered`);
        return res.status(400).json({
          success: false,
          message: 'User already registered with this WhatsApp number'
        });
      }
    }

    // Create new user
    console.log('✏️ Creating new user record...');
    const newUser = await User.create({
      username,
      dateOfBirth,
      passcode,
      referralCode,
      registrationMethod,
      telegramId: registrationMethod === 'telegram' ? telegramId : null,
      whatsappNumber: registrationMethod === 'whatsapp' ? whatsappNumber : null,
      mfaEnabled: true  // Enable MFA by default for all new users
    });
    console.log(`✅ User created with ID: ${newUser.id}`);

    // Assign default user role
    try {
      // Get the default role (usually 'user')
      let roleToAssign = 'user';
      
      // If an initialRole is specified and the request comes from an admin, use that instead
      if (initialRole && req.user && await req.user._dbUser.hasRole('admin')) {
        roleToAssign = initialRole;
      }
      
      const role = await Role.findOne({ where: { name: roleToAssign } });
      
      if (role) {
        // Create the user-role association
        await UserRole.create({
          userId: newUser.id,
          roleId: role.id,
          assignedBy: req.user ? req.user.id : null, // If available, use the admin who created this user
          assignedAt: new Date()
        });
        
        console.log(`✅ Assigned role '${roleToAssign}' to new user ${newUser.id}`);
      } else {
        console.warn(`⚠️ Could not find default role '${roleToAssign}' to assign to new user`);
      }
    } catch (roleError) {
      console.error('⚠️ Error assigning default role to user:', roleError);
      // Continue with registration even if role assignment fails
    }

    // Generate and send OTP for verification
    console.log(`🔑 Generating OTP for user ${username}...`);
    const otpSent = await createOTP(newUser, registrationMethod, 'REGISTRATION', req);
    
    if (!otpSent) {
      console.log(`⚠️ OTP could not be sent for user ${username}, but account was created`);
      return res.status(201).json({
        success: true,
        message: 'User registered successfully, but OTP could not be sent. Please check if you have started a conversation with our bot.',
        userId: newUser.id
      });
    }

    console.log(`✅ Registration successful for user ${username}`);
    res.status(201).json({
      success: true,
      message: 'User registered successfully. Please verify with the OTP sent.',
      userId: newUser.id
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during registration'
    });
  }
};

// Verify OTP
const verifyUserOTP = async (req, res) => {
  try {
    console.log('🔑 Processing OTP verification request:', req.body);
    const { userId, otp } = req.body;
    
    const result = await verifyOTP(userId, otp, req);
    
    if (!result.success) {
      console.log(`❌ OTP verification failed for user ${userId}: ${result.message}`);
      return res.status(400).json(result);
    }
    
    // Get the user for token generation
    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Generate tokens using the new token service
    const tokens = await generateTokens(user, req);
    
    console.log(`✅ OTP verification successful for user ${userId}`);
    res.status(200).json({
      success: true,
      message: 'User verified successfully',
      ...tokens,
      user: {
        id: user.id,
        username: user.username,
        registrationMethod: user.registrationMethod
      }
    });
  } catch (error) {
    console.error('❌ OTP verification error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during OTP verification'
    });
  }
};

// Login user - adding detailed logging
const loginUser = async (req, res) => {
  try {
    console.log('🔐 Processing login request:', { 
      username: req.body.username,
      ipAddress: req.ip 
    });
    
    const { username, passcode, loginMethod } = req.body;

    // Find user by username
    const user = await User.findOne({ where: { username } });
    
    if (!user) {
      console.log(`❌ Login failed: User ${username} not found`);
      
      // Log failed login attempt for non-existent user
      await logActivity({
        action: 'LOGIN',
        category: 'AUTH',
        severity: 'WARNING',
        details: {
          attemptedUsername: username,
          loginMethod,
          reason: 'User not found'
        },
        ipAddress: req.ip,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: '/api/auth/login',
        status: 'FAILURE'
      });
      
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check if user is verified
    if (!user.isVerified) {
      console.log(`⚠️ Login failed: User ${username} is not verified`);
      
      // Log failed login attempt for unverified user
      await logActivity({
        action: 'LOGIN',
        category: 'AUTH',
        severity: 'WARNING',
        details: {
          username,
          userId: user.id,
          loginMethod,
          reason: 'Account not verified'
        },
        ipAddress: req.ip,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: '/api/auth/login',
        status: 'FAILURE',
        userId: user.id
      });
      
      return res.status(401).json({
        success: false,
        message: 'Account not verified. Please verify your account first.'
      });
    }

    // Verify passcode
    const isPasscodeValid = await user.comparePasscode(passcode);
    
    if (!isPasscodeValid) {
      console.log(`❌ Login failed: Invalid passcode for user ${username}`);
      
      // Log the failed attempt
      await LoginAttempt.create({
        userId: user.id,
        successful: false,
        ipAddress: req.ip,
        loginMethod
      });
      
      // Log failed login due to invalid passcode
      await logActivity({
        action: 'LOGIN',
        category: 'AUTH',
        severity: 'WARNING',
        details: {
          username,
          userId: user.id,
          loginMethod,
          reason: 'Invalid passcode'
        },
        ipAddress: req.ip,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: '/api/auth/login',
        status: 'FAILURE',
        userId: user.id
      });
      
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // If MFA is enabled, send OTP and require second verification step
    if (user.mfaEnabled) {
      console.log(`👤 User ${username} has MFA enabled, sending OTP...`);
      
      // Check if user has made too many OTP requests recently
      const rateLimitCheck = await checkOTPRateLimit(user.id);
      if (rateLimitCheck.limited) {
        // Log rate limited OTP request
        await logActivity({
          action: 'OTP_RATE_LIMITED',
          category: 'MFA',
          severity: 'WARNING',
          details: {
            username,
            userId: user.id,
            loginMethod,
            reason: rateLimitCheck.message
          },
          ipAddress: req.ip,
          userAgent: req.get('user-agent') || 'Unknown',
          resourceId: '/api/auth/login',
          status: 'BLOCKED',
          userId: user.id
        });
        
        return res.status(429).json({
          success: false,
          message: rateLimitCheck.message,
          requireMFA: true
        });
      }
      
      // Request MFA OTP
      const mfaResult = await requestLoginMFA(user, req);
      
      if (!mfaResult.success) {
        // Log MFA request failure
        await logActivity({
          action: 'MFA_REQUEST_FAILED',
          category: 'MFA',
          severity: 'WARNING',
          details: {
            username,
            userId: user.id,
            loginMethod,
            reason: mfaResult.message
          },
          ipAddress: req.ip,
          userAgent: req.get('user-agent') || 'Unknown',
          resourceId: '/api/auth/login',
          status: 'FAILURE',
          userId: user.id
        });
        
        return res.status(400).json({
          ...mfaResult,
          requireMFA: true
        });
      }
      
      // Log successful first step
      await LoginAttempt.create({
        userId: user.id,
        successful: true,
        ipAddress: req.ip,
        loginMethod,
        mfaCompleted: false
      });
      
      // Log successful passcode verification, awaiting MFA
      await logActivity({
        action: 'PASSCODE_VERIFIED',
        category: 'AUTH',
        severity: 'INFO',
        details: {
          username,
          userId: user.id,
          loginMethod,
          mfaRequired: true
        },
        ipAddress: req.ip,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: '/api/auth/login',
        status: 'SUCCESS',
        userId: user.id
      });
      
      // Log MFA OTP sent
      await logActivity({
        action: 'MFA_OTP_SENT',
        category: 'MFA',
        severity: 'INFO',
        details: {
          username,
          userId: user.id,
          loginMethod,
          deliveryMethod: user.registrationMethod.toUpperCase()
        },
        ipAddress: req.ip,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: '/api/auth/login',
        status: 'SUCCESS',
        userId: user.id
      });
      
      console.log(`🔐 First authentication step successful for user ${username}, awaiting MFA verification`);
      return res.status(200).json({
        success: true,
        message: 'Please enter the OTP sent to complete login',
        requireMFA: true,
        userId: user.id
      });
    }
    
    // If MFA not enabled, generate tokens using the new token service
    const tokens = await generateTokens(user, req);
    
    // Log successful login attempt
    await LoginAttempt.create({
      userId: user.id,
      successful: true,
      ipAddress: req.ip,
      loginMethod,
      mfaCompleted: false  // MFA not required
    });
    
    // Log successful login without MFA
    await logActivity({
      action: 'LOGIN',
      category: 'AUTH',
      severity: 'INFO',
      details: {
        username,
        userId: user.id,
        loginMethod,
        mfaRequired: false
      },
      ipAddress: req.ip,
      userAgent: req.get('user-agent') || 'Unknown',
      resourceId: '/api/auth/login',
      status: 'SUCCESS',
      userId: user.id
    });
    
    // Update user's last login time
    await User.update(
      { lastLogin: new Date() },
      { where: { id: user.id } }
    );
    
    console.log(`✅ Login successful for user ${username} (MFA not required)`);
    res.status(200).json({
      success: true,
      message: 'Login successful',
      ...tokens,
      user: {
        id: user.id,
        username: user.username,
        registrationMethod: user.registrationMethod
      }
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    
    // Log login error
    await logActivity({
      action: 'LOGIN_ERROR',
      category: 'SYSTEM',
      severity: 'ERROR',
      details: {
        error: error.message,
        stack: error.stack
      },
      ipAddress: req.ip,
      userAgent: req.get('user-agent') || 'Unknown',
      resourceId: '/api/auth/login',
      status: 'FAILURE'
    }).catch(err => console.error('Failed to log login error:', err));
    
    res.status(500).json({
      success: false,
      message: 'An error occurred during login'
    });
  }
};

// Second step of login - verify MFA OTP
const verifyLoginMFA = async (req, res) => {
  try {
    console.log('🔐 Processing MFA verification for login:', req.body);
    const { userId, otp } = req.body;
    
    // Verify the OTP
    const verificationResult = await verifyOTP(userId, otp, req);
    if (!verificationResult.success) {
      return res.status(400).json(verificationResult);
    }
    
    // Find the user
    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Mark the login attempt as MFA-completed
    await LoginAttempt.update(
      { mfaCompleted: true },
      { 
        where: {
          userId: user.id,
          mfaCompleted: false
        },
        order: [['createdAt', 'DESC']],
        limit: 1
      }
    );
    
    // Generate tokens using the new token service
    const tokens = await generateTokens(user, req);
    
    // Update user's last login time
    await User.update(
      { lastLogin: new Date() },
      { where: { id: user.id } }
    );
    
    console.log(`✅ MFA verification successful for user ${user.username}`);
    res.status(200).json({
      success: true,
      message: 'Login successful',
      ...tokens,
      user: {
        id: user.id,
        username: user.username,
        registrationMethod: user.registrationMethod
      }
    });
  } catch (error) {
    console.error('❌ MFA verification error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during MFA verification'
    });
  }
};

// Toggle MFA setting for a user
const toggleMFA = async (req, res) => {
  try {
    // The user ID should be from the authenticated JWT token
    const userId = req.user.id;
    
    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Toggle MFA setting
    const newMfaSetting = !user.mfaEnabled;
    await User.update(
      { mfaEnabled: newMfaSetting },
      { where: { id: userId } }
    );
    
    console.log(`🔄 MFA ${newMfaSetting ? 'enabled' : 'disabled'} for user ${user.username}`);
    res.status(200).json({
      success: true,
      message: `Multi-factor authentication ${newMfaSetting ? 'enabled' : 'disabled'} successfully`,
      mfaEnabled: newMfaSetting
    });
  } catch (error) {
    console.error('❌ Toggle MFA error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while updating MFA settings'
    });
  }
};

// Test Telegram message sending
const testTelegramMessage = async (req, res) => {
  try {
    console.log('🧪 Processing test Telegram message request:', req.body);
    const { telegramId, message } = req.body;
    
    const result = await sendTestMessage(telegramId, message || 'This is a test message from the Authentication System');
    
    if (!result) {
      console.log(`❌ Test message failed to send to Telegram ID ${telegramId}`);
      return res.status(500).json({
        success: false,
        message: 'Failed to send test message. Make sure you have started a conversation with the bot.'
      });
    }
    
    console.log(`✅ Test message sent successfully to Telegram ID ${telegramId}`);
    res.status(200).json({
      success: true,
      message: 'Test message sent successfully!'
    });
  } catch (error) {
    console.error('❌ Test Telegram message error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while sending test message'
    });
  }
};

// Get MFA statistics for admin dashboard
const getMFAStats = async (req, res) => {
  try {
    // Ensure user is admin (middleware should handle this)
    
    // Get total users
    const totalUsers = await User.count();
    
    // Get users with MFA enabled
    const mfaEnabledUsers = await User.count({
      where: { mfaEnabled: true }
    });
    
    // Get OTP stats for last 30 days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const { Op } = require('sequelize');
    const otpStats = await OtpLog.count({
      attributes: ['status'],
      where: {
        createdAt: {
          [Op.gte]: thirtyDaysAgo
        }
      },
      group: ['status']
    });
    
    res.status(200).json({
      success: true,
      stats: {
        totalUsers,
        mfaEnabledUsers,
        mfaPercentage: (mfaEnabledUsers / totalUsers * 100).toFixed(2),
        otpStats
      }
    });
  } catch (error) {
    console.error('❌ MFA stats error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while retrieving MFA statistics'
    });
  }
};

// Export all functions
module.exports = {
  registerUser,
  verifyUserOTP,
  loginUser,
  verifyLoginMFA,
  toggleMFA,
  testTelegramMessage,
  getMFAStats
};