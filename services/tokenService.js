const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { User, Token } = require('../models'); // Changed this line
const { Op } = require('sequelize');
require('dotenv').config();

// Default expiration times
const ACCESS_TOKEN_EXPIRY = '1h';  // 1 hour
const REFRESH_TOKEN_EXPIRY = '7d'; // 7 days


/**
 * Generate a new set of tokens for a user
 * @param {Object} user - User object
 * @param {Object} req - Express request object for IP and user agent
 * @returns {Object} Object containing access token, refresh token, and expiry times
 */
const generateTokens = async (user, req) => {
  try {
    console.log(`🔑 Generating new tokens for user ${user.username}`);
    
    // Create a unique identifier for this refresh token
    const jti = uuidv4();
    
    // Get user roles for token payload
    const userRoles = await user.getRoles();
    const roles = userRoles.map(role => role.name);
    
    // Generate access token with shorter expiry
    const accessToken = jwt.sign(
      { 
        id: user.id,
        username: user.username,
        roles, // Include roles in the token
        type: 'access'
      },
      process.env.JWT_SECRET,
      { 
        expiresIn: ACCESS_TOKEN_EXPIRY
      }
    );
    
    // Generate refresh token with longer expiry
    const refreshToken = jwt.sign(
      { 
        id: user.id,
        username: user.username,
        roles, // Include roles in the refresh token as well
        type: 'refresh',
        jti // Include the unique identifier
      },
      process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
      { 
        expiresIn: REFRESH_TOKEN_EXPIRY
      }
    );
    
    // Calculate expiry timestamps
    const accessTokenExpiry = new Date();
    accessTokenExpiry.setHours(accessTokenExpiry.getHours() + 1); // 1 hour from now
    
    const refreshTokenExpiry = new Date();
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7); // 7 days from now
    
    // Store tokens in database
    const ipAddress = req ? (req.headers['x-forwarded-for'] || req.ip || '0.0.0.0') : '0.0.0.0';
    const userAgent = req ? (req.headers['user-agent'] || null) : null;
    
    // Simple device info extraction (can be enhanced)
    let deviceInfo = {};
    if (userAgent) {
      deviceInfo = {
        isMobile: /mobile/i.test(userAgent),
        browser: userAgent.split(' ').pop(),
        rawUserAgent: userAgent
      };
    }
    
    // Store the token in the database
    await Token.create({
      userId: user.id,
      accessToken,
      refreshToken,
      accessTokenExpiresAt: accessTokenExpiry,
      refreshTokenExpiresAt: refreshTokenExpiry,
      ipAddress,
      userAgent,
      deviceInfo,
      lastUsed: new Date()
    });
    
    console.log(`✅ Tokens generated and stored for user ${user.username}`);
    
    return {
      accessToken,
      refreshToken,
      expiresIn: 3600, // 1 hour in seconds
      refreshExpiresIn: 604800, // 7 days in seconds
      roles // Include roles in the response
    };
  } catch (error) {
    console.error('❌ Error generating tokens:', error);
    throw error;
  }
};

/**
 * Validate and refresh tokens
 * @param {string} refreshToken - The refresh token to validate
 * @param {Object} req - Express request object
 * @returns {Object} New tokens if refresh is successful
 */
const refreshTokens = async (refreshToken, req) => {
  try {
    console.log('🔄 Processing token refresh request');
    
    // First check if the token exists and is not revoked in our database
    const tokenRecord = await Token.findOne({
      where: {
        refreshToken,
        isRevoked: false,
        refreshTokenExpiresAt: {
          [Op.gt]: new Date() // Not expired
        }
      }
    });
    
    if (!tokenRecord) {
      console.log('❌ Refresh token not found or revoked');
      throw new Error('Invalid refresh token');
    }
    
    // Verify the refresh token
    let decoded;
    try {
      decoded = jwt.verify(
        refreshToken, 
        process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET
      );
    } catch (error) {
      console.error('❌ JWT verification failed:', error.message);
      
      // If token is invalid, revoke it
      await Token.update(
        { isRevoked: true },
        { where: { refreshToken } }
      );
      
      throw new Error('Invalid refresh token');
    }
    
    // Check token type
    if (decoded.type !== 'refresh') {
      console.log('❌ Not a refresh token');
      throw new Error('Invalid token type');
    }
    
    // Get the user
    const user = await User.findByPk(decoded.id);
    if (!user) {
      console.log('❌ User not found for refresh token');
      throw new Error('User not found');
    }
    
    // Check if user account is locked
    if (user.accountLocked) {
      if (user.accountLockedUntil && new Date() < new Date(user.accountLockedUntil)) {
        throw new Error('Account is locked');
      } else {
        // If lock period has passed, unlock the account
        await User.update(
          { 
            accountLocked: false, 
            accountLockedUntil: null,
            failedLoginAttempts: 0
          },
          { where: { id: user.id } }
        );
      }
    }
    
    // Revoke the old token
    await Token.update(
      { isRevoked: true },
      { where: { id: tokenRecord.id } }
    );
    
    // Generate new tokens
    const newTokens = await generateTokens(user, req);
    
    // Update user's last login time
    await User.update(
      { lastLogin: new Date() },
      { where: { id: user.id } }
    );
    
    console.log(`✅ Token refreshed successfully for user ${user.username}`);
    return {
      ...newTokens,
      user: {
        id: user.id,
        username: user.username,
        registrationMethod: user.registrationMethod
      }
    };
  } catch (error) {
    console.error('❌ Error refreshing token:', error);
    throw error;
  }
};

/**
 * Revoke a specific token
 * @param {string} refreshToken - The refresh token to revoke
 * @returns {boolean} Success status
 */
const revokeToken = async (refreshToken) => {
  try {
    console.log('🚫 Processing token revocation request');
    
    // Find and revoke the token
    const result = await Token.update(
      { isRevoked: true },
      { 
        where: { 
          refreshToken,
          isRevoked: false
        } 
      }
    );
    
    const success = result[0] > 0;
    console.log(`${success ? '✅' : '❌'} Token revocation ${success ? 'successful' : 'failed'}`);
    
    return success;
  } catch (error) {
    console.error('❌ Error revoking token:', error);
    throw error;
  }
};

/**
 * Revoke all tokens for a user
 * @param {string} userId - The user ID
 * @returns {number} Number of tokens revoked
 */
const revokeAllUserTokens = async (userId) => {
  try {
    console.log(`🚫 Revoking all tokens for user ${userId}`);
    
    const result = await Token.update(
      { isRevoked: true },
      { 
        where: { 
          userId,
          isRevoked: false
        } 
      }
    );
    
    console.log(`✅ Revoked ${result[0]} tokens for user ${userId}`);
    return result[0];
  } catch (error) {
    console.error('❌ Error revoking user tokens:', error);
    throw error;
  }
};

/**
 * Get all active sessions for a user
 * @param {string} userId - The user ID
 * @returns {Array} List of active sessions
 */
const getUserActiveSessions = async (userId) => {
  try {
    console.log(`🔍 Fetching active sessions for user ${userId}`);
    
    const tokens = await Token.findAll({
      where: {
        userId,
        isRevoked: false,
        refreshTokenExpiresAt: {
          [Op.gt]: new Date() // Not expired
        }
      },
      attributes: ['id', 'ipAddress', 'userAgent', 'deviceInfo', 'createdAt', 'lastUsed']
    });
    
    console.log(`✅ Found ${tokens.length} active sessions for user ${userId}`);
    
    // Format the sessions for user-friendly display
    return tokens.map(token => ({
      id: token.id,
      ipAddress: token.ipAddress,
      device: token.deviceInfo ? 
        (token.deviceInfo.isMobile ? 'Mobile' : 'Desktop') : 
        'Unknown',
      browser: token.deviceInfo ? token.deviceInfo.browser : 'Unknown',
      createdAt: token.createdAt,
      lastUsed: token.lastUsed
    }));
  } catch (error) {
    console.error('❌ Error fetching user sessions:', error);
    throw error;
  }
};

/**
 * Clean up expired tokens (can be run as a scheduled job)
 * @returns {number} Number of tokens deleted
 */
const cleanupExpiredTokens = async () => {
  try {
    console.log('🧹 Cleaning up expired tokens');
    
    const result = await Token.destroy({
      where: {
        [Op.or]: [
          { 
            refreshTokenExpiresAt: {
              [Op.lt]: new Date() // Expired refresh tokens
            } 
          },
          { 
            isRevoked: true,
            updatedAt: {
              [Op.lt]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Revoked tokens older than 30 days
            }
          }
        ]
      }
    });
    
    console.log(`✅ Deleted ${result} expired tokens`);
    return result;
  } catch (error) {
    console.error('❌ Error cleaning up tokens:', error);
    throw error;
  }
};

module.exports = {
  generateTokens,
  refreshTokens,
  revokeToken,
  revokeAllUserTokens,
  getUserActiveSessions,
  cleanupExpiredTokens
};