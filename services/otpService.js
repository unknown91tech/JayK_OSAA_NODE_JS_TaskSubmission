const { User, OtpLog } = require('../models');  // Changed this line
const { generateOTP, sendOTP } = require('./telegramService');
const { Op } = require('sequelize');

// Create and store OTP for a user with enhanced logging
const createOTP = async (user, method, otpType = 'LOGIN', req = null) => {
  // Generate a new 6-digit OTP
  const otp = generateOTP();
  console.log(`🔢 Generated OTP ${otp} for user ${user.username} using ${method} for ${otpType}`);
  
  // OTP will expire in 10 minutes
  const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
  
  // Store OTP in user record
  await User.update(
    {
      otpSecret: otp,
      otpExpiresAt
    },
    { where: { id: user.id } }
  );
  console.log(`💾 OTP stored in database for user ${user.username}`);
  
  // Create OTP log entry
  const ipAddress = req ? (req.headers['x-forwarded-for'] || req.ip || '0.0.0.0') : '0.0.0.0';
  const userAgent = req ? (req.headers['user-agent'] || null) : null;
  
  const otpLog = await OtpLog.create({
    userId: user.id,
    otpType,
    ipAddress,
    userAgent,
    status: 'GENERATED',
    deliveryMethod: method.toUpperCase(),
    validUntil: otpExpiresAt
  });
  
  // Send OTP based on delivery method
  let deliveryStatus = false;
  
  if (method === 'telegram' && user.telegramId) {
    console.log(`📱 Attempting to send OTP via Telegram to ID: ${user.telegramId}`);
    deliveryStatus = await sendOTP(user.telegramId, otp);
    console.log(`📱 OTP send attempt result: ${deliveryStatus ? 'Success ✅' : 'Failed ❌'}`);
  } 
  else if (method === 'whatsapp' && user.whatsappNumber) {
    // WhatsApp implementation placeholder (for future)
    console.log('⚠️ WhatsApp delivery not yet implemented');
    deliveryStatus = false;
  }
  
  // Update OTP log with delivery status
  await OtpLog.update(
    {
      status: deliveryStatus ? 'DELIVERED' : 'FAILED',
      failureReason: deliveryStatus ? null : 'Failed to deliver OTP'
    },
    { where: { id: otpLog.id } }
  );
  
  return deliveryStatus;
};

// Verify OTP provided by user with enhanced security and logging
const verifyOTP = async (userId, providedOTP, req = null) => {
  const user = await User.findByPk(userId);
  
  if (!user) {
    console.log(`❌ OTP verification failed: User ${userId} not found`);
    return { success: false, message: 'User not found' };
  }
  
  console.log(`🔍 Verifying OTP for user ${user.username}: Provided=${providedOTP}, Stored=${user.otpSecret}`);
  
  // Get the most recent OTP log for this user
  const otpLog = await OtpLog.findOne({
    where: {
      userId: user.id,
      status: {
        [Op.in]: ['GENERATED', 'DELIVERED']
      }
    },
    order: [['createdAt', 'DESC']]
  });
  
  // Check if OTP is expired
  if (!user.otpSecret || !user.otpExpiresAt || new Date() > new Date(user.otpExpiresAt)) {
    console.log(`⏰ OTP expired for user ${user.username}`);
    
    // Update OTP log if it exists
    if (otpLog) {
      await OtpLog.update(
        {
          status: 'EXPIRED',
          failureReason: 'OTP expired'
        },
        { where: { id: otpLog.id } }
      );
    }
    
    return { success: false, message: 'OTP expired' };
  }
  
  // Check if OTP matches
  if (user.otpSecret !== providedOTP) {
    console.log(`❌ Invalid OTP for user ${user.username}`);
    
    // Update OTP log if it exists
    if (otpLog) {
      await OtpLog.update(
        {
          status: 'FAILED',
          failureReason: 'Invalid OTP provided'
        },
        { where: { id: otpLog.id } }
      );
    }
    
    return { success: false, message: 'Invalid OTP' };
  }
  
  // Mark user as verified and clear OTP data
  await User.update(
    {
      isVerified: true,
      otpSecret: null,
      otpExpiresAt: null
    },
    { where: { id: user.id } }
  );
  
  // Update OTP log if it exists
  if (otpLog) {
    await OtpLog.update(
      {
        status: 'VERIFIED',
        verifiedAt: new Date()
      },
      { where: { id: otpLog.id } }
    );
  }
  
  console.log(`✅ OTP verified successfully for user ${user.username}`);
  return { success: true, message: 'OTP verified successfully' };
};

// Function to request an MFA OTP for existing user login
const requestLoginMFA = async (user, req) => {
  // Determine which method to use for OTP delivery
  const deliveryMethod = user.registrationMethod || 'telegram';
  
  // Generate and send OTP
  const otpSent = await createOTP(user, deliveryMethod, 'LOGIN', req);
  
  if (!otpSent) {
    return {
      success: false,
      message: 'Could not send OTP for verification. Please ensure you have started a conversation with our bot if using Telegram.'
    };
  }
  
  return {
    success: true,
    message: 'OTP sent successfully for verification.',
    userId: user.id
  };
};

// Check if a user has recently requested too many OTPs (rate limiting)
const checkOTPRateLimit = async (userId) => {
  // Count OTPs generated in the last 15 minutes
  const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
  
  const recentOTPs = await OtpLog.count({
    where: {
      userId,
      createdAt: {
        [Op.gte]: fifteenMinutesAgo
      }
    }
  });
  
  // If more than 5 OTPs were requested in the last 15 minutes, rate limit
  if (recentOTPs >= 5) {
    return {
      limited: true,
      message: 'Too many OTP requests. Please try again later.'
    };
  }
  
  return { limited: false };
};

module.exports = {
  createOTP,
  verifyOTP,
  requestLoginMFA,
  checkOTPRateLimit
};