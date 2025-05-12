const { 
  refreshTokens, 
  revokeToken, 
  revokeAllUserTokens, 
  getUserActiveSessions 
} = require('../services/tokenService');

/**
 * Refresh access token using a valid refresh token
 */
const refreshUserTokens = async (req, res) => {
  try {
    console.log('🔄 Processing token refresh');
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required'
      });
    }
    
    // Attempt to refresh tokens
    const tokens = await refreshTokens(refreshToken, req);
    
    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      ...tokens
    });
  } catch (error) {
    console.error('❌ Token refresh error:', error);
    res.status(401).json({
      success: false,
      message: error.message || 'Invalid refresh token'
    });
  }
};

/**
 * Logout user by revoking their refresh token
 */
const logoutUser = async (req, res) => {
  try {
    console.log('🚪 Processing logout request');
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required'
      });
    }
    
    // Revoke the token
    const success = await revokeToken(refreshToken);
    
    if (success) {
      res.status(200).json({
        success: true,
        message: 'Logged out successfully'
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Invalid token or already logged out'
      });
    }
  } catch (error) {
    console.error('❌ Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during logout'
    });
  }
};

/**
 * Logout user from all devices by revoking all their tokens
 */
const logoutFromAllDevices = async (req, res) => {
  try {
    console.log('🚪 Processing logout from all devices');
    // Get user ID from JWT token (set by authentication middleware)
    const userId = req.user.id;
    
    // Revoke all tokens for the user
    const count = await revokeAllUserTokens(userId);
    
    res.status(200).json({
      success: true,
      message: `Successfully logged out from ${count} device(s)`
    });
  } catch (error) {
    console.error('❌ Logout from all devices error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during logout'
    });
  }
};

/**
 * Get user's active sessions
 */
const getUserSessions = async (req, res) => {
  try {
    console.log('🔍 Fetching user sessions');
    // Get user ID from JWT token (set by authentication middleware)
    const userId = req.user.id;
    
    // Get active sessions
    const sessions = await getUserActiveSessions(userId);
    
    res.status(200).json({
      success: true,
      sessions
    });
  } catch (error) {
    console.error('❌ Error fetching user sessions:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while fetching sessions'
    });
  }
};

/**
 * Terminate a specific session
 */
const terminateSession = async (req, res) => {
  try {
    console.log('🔌 Terminating specific session');
    const { sessionId } = req.params;
    const userId = req.user.id;
    
    // Get the session token (to ensure it belongs to the user)
    const Token = require('../models/Token');
    const token = await Token.findOne({
      where: {
        id: sessionId,
        userId
      }
    });
    
    if (!token) {
      return res.status(404).json({
        success: false,
        message: 'Session not found'
      });
    }
    
    // Revoke the token
    await Token.update(
      { isRevoked: true },
      { where: { id: sessionId } }
    );
    
    res.status(200).json({
      success: true,
      message: 'Session terminated successfully'
    });
  } catch (error) {
    console.error('❌ Error terminating session:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while terminating the session'
    });
  }
};

module.exports = {
  refreshUserTokens,
  logoutUser,
  logoutFromAllDevices,
  getUserSessions,
  terminateSession
};