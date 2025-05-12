const jwt = require('jsonwebtoken');
const { User } = require('../models');
const Token = require('../models/Token');
const { Op } = require('sequelize');
const { logActivity } = require('../services/loggerService');
require('dotenv').config();

// Middleware to validate access tokens and protect routes
const authenticateToken = async (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN format
    
    if (!token) {
      // Log missing token
      await logActivity({
        action: 'AUTHENTICATION_FAILURE',
        category: 'SECURITY',
        severity: 'WARNING',
        details: {
          reason: 'Missing token',
          path: req.originalUrl
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: req.originalUrl,
        status: 'FAILURE'
      });
      
      return res.status(401).json({
        success: false,
        message: 'Authentication token required'
      });
    }
    
    // Verify token
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        console.error('❌ Token verification failed:', err.message);
        
        // Log token verification failure
        await logActivity({
          action: 'TOKEN_VERIFICATION_FAILURE',
          category: 'SECURITY',
          severity: 'WARNING',
          details: {
            reason: err.message,
            path: req.originalUrl
          },
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.get('user-agent') || 'Unknown',
          resourceId: req.originalUrl,
          status: 'FAILURE'
        });
        
        // Check if token is expired
        if (err.name === 'TokenExpiredError') {
          return res.status(401).json({
            success: false,
            message: 'Token expired',
            code: 'TOKEN_EXPIRED'
          });
        }
        
        return res.status(403).json({
          success: false,
          message: 'Invalid token'
        });
      }
      
      // Check token type (ensure it's an access token)
      if (decoded.type && decoded.type !== 'access') {
        // Log invalid token type
        await logActivity({
          action: 'INVALID_TOKEN_TYPE',
          category: 'SECURITY',
          severity: 'WARNING',
          details: {
            expectedType: 'access',
            receivedType: decoded.type,
            path: req.originalUrl
          },
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.get('user-agent') || 'Unknown',
          resourceId: req.originalUrl,
          status: 'FAILURE'
        });
        
        return res.status(403).json({
          success: false,
          message: 'Invalid token type'
        });
      }
      
      // Find user from decoded token
      const user = await User.findByPk(decoded.id, {
        include: ['Roles'] // Include roles for role-based authorization
      });
      
      if (!user) {
        // Log user not found
        await logActivity({
          action: 'USER_NOT_FOUND',
          category: 'SECURITY',
          severity: 'WARNING',
          details: {
            userId: decoded.id,
            path: req.originalUrl
          },
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.get('user-agent') || 'Unknown',
          resourceId: req.originalUrl,
          status: 'FAILURE'
        });
        
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
      
      // Check if user account is locked
      if (user.accountLocked) {
        if (user.accountLockedUntil && new Date() < new Date(user.accountLockedUntil)) {
          // Log account locked access attempt
          await logActivity({
            action: 'LOCKED_ACCOUNT_ACCESS_ATTEMPT',
            category: 'SECURITY',
            severity: 'WARNING',
            details: {
              userId: user.id,
              username: user.username,
              lockedUntil: user.accountLockedUntil,
              path: req.originalUrl
            },
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('user-agent') || 'Unknown',
            resourceId: req.originalUrl,
            status: 'BLOCKED',
            userId: user.id
          });
          
          return res.status(403).json({
            success: false,
            message: 'Account is temporarily locked. Please try again later.'
          });
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
          
          // Log account auto-unlock
          await logActivity({
            action: 'ACCOUNT_AUTO_UNLOCK',
            category: 'SECURITY',
            severity: 'INFO',
            details: {
              userId: user.id,
              username: user.username,
              reason: 'Lock period expired'
            },
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('user-agent') || 'Unknown',
            resourceId: req.originalUrl,
            status: 'SUCCESS',
            userId: user.id
          });
        }
      }
      
      // Extract roles for easier access
      const roles = user.Roles ? user.Roles.map(role => role.name) : [];
      
      // Add user info to request object
      req.user = {
        id: user.id,
        username: user.username,
        registrationMethod: user.registrationMethod,
        mfaEnabled: user.mfaEnabled,
        roles: roles, // Include roles in the req.user object
        _dbUser: user // Store the full user object for advanced role checks
      };
      
      // Update token last used timestamp
      await Token.update(
        { lastUsed: new Date() },
        { 
          where: { 
            userId: user.id,
            accessToken: token,
            isRevoked: false
          } 
        }
      );
      
      // Log successful authentication
      await logActivity({
        action: 'AUTHENTICATION_SUCCESS',
        category: 'AUTH',
        severity: 'INFO',
        details: {
          userId: user.id,
          username: user.username,
          roles: roles,
          path: req.originalUrl
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: req.originalUrl,
        status: 'SUCCESS',
        userId: user.id
      });
      
      next();
    });
  } catch (error) {
    console.error('❌ Authentication error:', error);
    
    // Log authentication error
    await logActivity({
      action: 'AUTHENTICATION_ERROR',
      category: 'SECURITY',
      severity: 'ERROR',
      details: {
        error: error.message,
        path: req.originalUrl
      },
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('user-agent') || 'Unknown',
      resourceId: req.originalUrl,
      status: 'FAILURE'
    }).catch(err => console.error('Failed to log authentication error:', err));
    
    res.status(500).json({
      success: false,
      message: 'An error occurred during authentication'
    });
  }
};

// Middleware to validate refresh tokens for token refresh endpoint
const authenticateRefreshToken = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      // Log missing refresh token
      await logActivity({
        action: 'REFRESH_TOKEN_MISSING',
        category: 'AUTH',
        severity: 'WARNING',
        details: {
          path: req.originalUrl
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: req.originalUrl,
        status: 'FAILURE'
      });
      
      return res.status(401).json({
        success: false,
        message: 'Refresh token required'
      });
    }
    
    // Check if token exists and is not revoked in our database
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
      // Log invalid refresh token
      await logActivity({
        action: 'INVALID_REFRESH_TOKEN',
        category: 'AUTH',
        severity: 'WARNING',
        details: {
          path: req.originalUrl,
          reason: 'Token not found, revoked, or expired'
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: req.originalUrl,
        status: 'FAILURE'
      });
      
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired refresh token'
      });
    }
    
    // Verify the token using JWT
    jwt.verify(
      refreshToken, 
      process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET, 
      async (err, decoded) => {
        if (err) {
          console.error('❌ Refresh token verification failed:', err.message);
          
          // Log refresh token verification failure
          await logActivity({
            action: 'REFRESH_TOKEN_VERIFICATION_FAILURE',
            category: 'SECURITY',
            severity: 'WARNING',
            details: {
              reason: err.message,
              path: req.originalUrl,
              tokenId: tokenRecord.id
            },
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('user-agent') || 'Unknown',
            resourceId: req.originalUrl,
            status: 'FAILURE',
            userId: tokenRecord.userId
          });
          
          // Revoke the token if it's invalid
          await Token.update(
            { isRevoked: true },
            { where: { refreshToken } }
          );
          
          return res.status(403).json({
            success: false,
            message: 'Invalid refresh token'
          });
        }
        
        // Check token type
        if (decoded.type !== 'refresh') {
          // Log invalid token type
          await logActivity({
            action: 'INVALID_TOKEN_TYPE',
            category: 'SECURITY',
            severity: 'WARNING',
            details: {
              expectedType: 'refresh',
              receivedType: decoded.type,
              path: req.originalUrl
            },
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('user-agent') || 'Unknown',
            resourceId: req.originalUrl,
            status: 'FAILURE',
            userId: tokenRecord.userId
          });
          
          return res.status(403).json({
            success: false,
            message: 'Invalid token type'
          });
        }
        
        // Log successful refresh token authentication
        await logActivity({
          action: 'REFRESH_TOKEN_VALIDATED',
          category: 'AUTH',
          severity: 'INFO',
          details: {
            tokenId: tokenRecord.id,
            userId: decoded.id,
            username: decoded.username
          },
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.get('user-agent') || 'Unknown',
          resourceId: req.originalUrl,
          status: 'SUCCESS',
          userId: decoded.id
        });
        
        // Add token data to request for use in controller
        req.tokenData = {
          userId: decoded.id,
          username: decoded.username,
          tokenId: tokenRecord.id
        };
        
        next();
      }
    );
  } catch (error) {
    console.error('❌ Refresh token authentication error:', error);
    
    // Log refresh token authentication error
    await logActivity({
      action: 'REFRESH_TOKEN_ERROR',
      category: 'SECURITY',
      severity: 'ERROR',
      details: {
        error: error.message,
        path: req.originalUrl
      },
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('user-agent') || 'Unknown',
      resourceId: req.originalUrl,
      status: 'FAILURE'
    }).catch(err => console.error('Failed to log refresh token error:', err));
    
    res.status(500).json({
      success: false,
      message: 'An error occurred during token authentication'
    });
  }
};

// Middleware to check if user has admin role
const isAdmin = async (req, res, next) => {
  try {
    if (!req.user || !req.user._dbUser) {
      // Log unauthorized admin access attempt
      await logActivity({
        action: 'UNAUTHORIZED_ADMIN_ACCESS',
        category: 'SECURITY',
        severity: 'WARNING',
        details: {
          path: req.originalUrl,
          reason: 'No authenticated user'
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: req.originalUrl,
        status: 'BLOCKED'
      });
      
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    const hasAdminRole = await req.user._dbUser.hasRole('admin');
    
    if (hasAdminRole) {
      // Log successful admin access
      await logActivity({
        action: 'ADMIN_ACCESS',
        category: 'ACCESS',
        severity: 'INFO',
        details: {
          userId: req.user.id,
          username: req.user.username,
          path: req.originalUrl
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: req.originalUrl,
        status: 'SUCCESS',
        userId: req.user.id
      });
      
      next();
    } else {
      // Log unauthorized admin access attempt
      await logActivity({
        action: 'UNAUTHORIZED_ADMIN_ACCESS',
        category: 'SECURITY',
        severity: 'WARNING',
        details: {
          userId: req.user.id,
          username: req.user.username,
          roles: req.user.roles,
          path: req.originalUrl
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: req.originalUrl,
        status: 'BLOCKED',
        userId: req.user.id
      });
      
      res.status(403).json({
        success: false,
        message: 'Access denied. Admin privileges required.'
      });
    }
  } catch (error) {
    console.error('❌ Role authorization error:', error);
    
    // Log role authorization error
    await logActivity({
      action: 'ROLE_AUTHORIZATION_ERROR',
      category: 'SECURITY',
      severity: 'ERROR',
      details: {
        error: error.message,
        path: req.originalUrl,
        userId: req.user ? req.user.id : null
      },
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('user-agent') || 'Unknown',
      resourceId: req.originalUrl,
      status: 'FAILURE',
      userId: req.user ? req.user.id : null
    }).catch(err => console.error('Failed to log role authorization error:', err));
    
    res.status(500).json({
      success: false,
      message: 'An error occurred during role authorization'
    });
  }
};

// Middleware to check if user has any of the specified roles
const hasRole = (roles) => {
  return async (req, res, next) => {
    try {
      if (!req.user || !req.user._dbUser) {
        // Log unauthorized role access attempt
        await logActivity({
          action: 'UNAUTHORIZED_ROLE_ACCESS',
          category: 'SECURITY',
          severity: 'WARNING',
          details: {
            path: req.originalUrl,
            requiredRoles: Array.isArray(roles) ? roles : [roles],
            reason: 'No authenticated user'
          },
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.get('user-agent') || 'Unknown',
          resourceId: req.originalUrl,
          status: 'BLOCKED'
        });
        
        return res.status(401).json({
          success: false,
          message: 'Authentication required'
        });
      }
      
      const roleArray = Array.isArray(roles) ? roles : [roles];
      const hasRequiredRole = await req.user._dbUser.hasAnyRole(roleArray);
      
      if (hasRequiredRole) {
        // Log successful role-based access
        await logActivity({
          action: 'ROLE_ACCESS',
          category: 'ACCESS',
          severity: 'INFO',
          details: {
            userId: req.user.id,
            username: req.user.username,
            requiredRoles: roleArray,
            userRoles: req.user.roles,
            path: req.originalUrl
          },
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.get('user-agent') || 'Unknown',
          resourceId: req.originalUrl,
          status: 'SUCCESS',
          userId: req.user.id
        });
        
        next();
      } else {
        // Log unauthorized role access attempt
        await logActivity({
          action: 'UNAUTHORIZED_ROLE_ACCESS',
          category: 'SECURITY',
          severity: 'WARNING',
          details: {
            userId: req.user.id,
            username: req.user.username,
            requiredRoles: roleArray,
            userRoles: req.user.roles,
            path: req.originalUrl
          },
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.get('user-agent') || 'Unknown',
          resourceId: req.originalUrl,
          status: 'BLOCKED',
          userId: req.user.id
        });
        
        res.status(403).json({
          success: false,
          message: `Access denied. Required role: ${roleArray.join(' or ')}`
        });
      }
    } catch (error) {
      console.error('❌ Role authorization error:', error);
      
      // Log role authorization error
      await logActivity({
        action: 'ROLE_AUTHORIZATION_ERROR',
        category: 'SECURITY',
        severity: 'ERROR',
        details: {
          error: error.message,
          path: req.originalUrl,
          userId: req.user ? req.user.id : null,
          requiredRoles: Array.isArray(roles) ? roles : [roles]
        },
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent') || 'Unknown',
        resourceId: req.originalUrl,
        status: 'FAILURE',
        userId: req.user ? req.user.id : null
      }).catch(err => console.error('Failed to log role authorization error:', err));
      
      res.status(500).json({
        success: false,
        message: 'An error occurred during role authorization'
      });
    }
  };
};

module.exports = {
  authenticateToken,
  authenticateRefreshToken,
  isAdmin,
  hasRole
};