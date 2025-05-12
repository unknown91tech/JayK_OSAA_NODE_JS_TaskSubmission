const Challenge = require('../models/Challenge');
const { User, LoginAttempt } = require('../models');
const { Op } = require('sequelize');
const { logActivity } = require('./loggerService');
const crypto = require('crypto');

// Challenge types with their difficulty levels
const CHALLENGE_TYPES = {
  CAPTCHA: 'CAPTCHA',
  MATH_PROBLEM: 'MATH_PROBLEM'
};

// Configuration
const FAILED_ATTEMPTS_THRESHOLD = 3;
const CHALLENGE_EXPIRY_MINUTES = 10;

/**
 * Generate a random CAPTCHA-like challenge
 * For demo purposes, we'll create a simple alphanumeric challenge
 */
const generateCaptchaChallenge = () => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  
  // Generate 5-character CAPTCHA
  for (let i = 0; i < 5; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  
  // Create ASCII art representation (simplified)
  const asciiArt = createAsciiArt(result);
  
  return {
    type: 'CAPTCHA',
    question: 'Please enter the characters shown in the image',
    image: asciiArt, // In production, this would be an actual image
    answer: result
  };
};

/**
 * Generate a simple math problem challenge
 */
const generateMathChallenge = () => {
  const operators = ['+', '-', '*'];
  const operator = operators[Math.floor(Math.random() * operators.length)];
  
  let num1, num2, answer;
  
  switch (operator) {
    case '+':
      num1 = Math.floor(Math.random() * 50) + 1;
      num2 = Math.floor(Math.random() * 50) + 1;
      answer = num1 + num2;
      break;
    case '-':
      num1 = Math.floor(Math.random() * 50) + 10;
      num2 = Math.floor(Math.random() * num1);
      answer = num1 - num2;
      break;
    case '*':
      num1 = Math.floor(Math.random() * 10) + 1;
      num2 = Math.floor(Math.random() * 10) + 1;
      answer = num1 * num2;
      break;
  }
  
  return {
    type: 'MATH_PROBLEM',
    question: `What is ${num1} ${operator} ${num2}?`,
    answer: answer.toString()
  };
};

/**
 * Create simple ASCII art for CAPTCHA (demo version)
 */
const createAsciiArt = (text) => {
  // This is a simplified version. In production, you'd generate actual images
  const lines = ['', '', '', '', ''];
  
  for (const char of text) {
    switch (char) {
      case 'A':
        lines[0] += ' ██  ';
        lines[1] += '████ ';
        lines[2] += '██ ██';
        lines[3] += '██ ██';
        lines[4] += '     ';
        break;
      case 'B':
        lines[0] += '███  ';
        lines[1] += '█  █ ';
        lines[2] += '███  ';
        lines[3] += '█  █ ';
        lines[4] += '███  ';
        break;
      // Add more characters as needed
      default:
        lines[0] += char + '    ';
        lines[1] += char + '    ';
        lines[2] += char + '    ';
        lines[3] += char + '    ';
        lines[4] += '     ';
    }
  }
  
  return lines.join('\n');
};

/**
 * Check if a user/IP needs a challenge
 * @param {string} userId - User ID (if known)
 * @param {string} ipAddress - IP address
 * @returns {Promise<boolean>} Whether a challenge is needed
 */
const needsChallenge = async (userId, ipAddress) => {
  try {
    // Check IP-based failed attempts in the last 15 minutes
    const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
    
    let whereClause = {
      ipAddress,
      successful: false,
      createdAt: {
        [Op.gte]: fifteenMinutesAgo
      }
    };
    
    // If userId is provided, also check user-specific attempts
    if (userId) {
      whereClause = {
        [Op.or]: [
          { ipAddress, successful: false },
          { userId, successful: false }
        ],
        createdAt: {
          [Op.gte]: fifteenMinutesAgo
        }
      };
    }
    
    const failedAttempts = await LoginAttempt.count({ where: whereClause });
    
    console.log(`🔍 Failed attempts check: ${failedAttempts} failures for IP ${ipAddress}${userId ? ` / User ${userId}` : ''}`);
    
    return failedAttempts >= FAILED_ATTEMPTS_THRESHOLD;
  } catch (error) {
    console.error('❌ Error checking challenge necessity:', error);
    return false;
  }
};

/**
 * Create a new challenge for a user/IP
 * @param {string|null} userId - User ID (if known)
 * @param {string} ipAddress - IP address
 * @param {Object} req - Express request object
 * @returns {Promise<Object>} Challenge details
 */
const createChallenge = async (userId, ipAddress, req) => {
  try {
    console.log(`🧩 Creating challenge for ${userId ? `user ${userId}` : 'IP'} ${ipAddress}`);
    
    // Check if there's already an active challenge for this IP/user
    const existingChallenge = await Challenge.findOne({
      where: {
        [Op.or]: [
          { userId },
          { ipAddress }
        ],
        isCorrect: null, // Not yet completed
        expiresAt: {
          [Op.gt]: new Date()
        }
      }
    });
    
    if (existingChallenge) {
      console.log('🔄 Found existing challenge, returning it');
      return {
        id: existingChallenge.id,
        type: existingChallenge.challengeType,
        challenge: existingChallenge.challengeData,
        expiresAt: existingChallenge.expiresAt
      };
    }
    
    // Generate a random challenge type
    const challengeTypes = Object.values(CHALLENGE_TYPES);
    const challengeType = challengeTypes[Math.floor(Math.random() * challengeTypes.length)];
    
    let challengeDetails;
    switch (challengeType) {
      case CHALLENGE_TYPES.CAPTCHA:
        challengeDetails = generateCaptchaChallenge();
        break;
      case CHALLENGE_TYPES.MATH_PROBLEM:
        challengeDetails = generateMathChallenge();
        break;
      default:
        challengeDetails = generateMathChallenge();
    }
    
    // Set expiry time
    const expiresAt = new Date(Date.now() + CHALLENGE_EXPIRY_MINUTES * 60 * 1000);
    
    // Create challenge record
    const challenge = await Challenge.create({
      userId,
      ipAddress,
      challengeType: challengeDetails.type,
      challengeData: {
        question: challengeDetails.question,
        image: challengeDetails.image || null
      },
      correctAnswer: challengeDetails.answer,
      expiresAt,
      userAgent: req ? req.get('user-agent') : null,
      sessionData: {
        timestamp: new Date().toISOString(),
        requestPath: req ? req.originalUrl : null
      }
    });
    
    // Log challenge creation
    await logActivity({
      action: 'CHALLENGE_CREATED',
      category: 'SECURITY',
      severity: 'WARNING',
      details: {
        challengeId: challenge.id,
        challengeType: challengeDetails.type,
        userId,
        ipAddress,
        reason: 'Multiple failed login attempts'
      },
      ipAddress,
      userAgent: req ? req.get('user-agent') : 'Unknown',
      resourceId: '/api/auth/challenge',
      status: 'SUCCESS',
      userId
    });
    
    console.log(`✅ Challenge created with ID: ${challenge.id}`);
    
    return {
      id: challenge.id,
      type: challengeDetails.type,
      challenge: challenge.challengeData,
      expiresAt: challenge.expiresAt
    };
  } catch (error) {
    console.error('❌ Error creating challenge:', error);
    throw error;
  }
};

/**
 * Verify a challenge answer
 * @param {string} challengeId - Challenge ID
 * @param {string} answer - User's answer
 * @param {Object} req - Express request object
 * @returns {Promise<Object>} Verification result
 */
const verifyChallenge = async (challengeId, answer, req) => {
  try {
    console.log(`🔍 Verifying challenge ${challengeId} with answer: ${answer}`);
    
    // Find the challenge
    const challenge = await Challenge.findByPk(challengeId);
    
    if (!challenge) {
      return {
        success: false,
        message: 'Challenge not found',
        code: 'CHALLENGE_NOT_FOUND'
      };
    }
    
    // Check if challenge is expired
    if (new Date() > challenge.expiresAt) {
      await Challenge.update(
        { 
          userAnswer: answer,
          isCorrect: false,
          completedAt: new Date()
        },
        { where: { id: challengeId } }
      );
      
      await logActivity({
        action: 'CHALLENGE_EXPIRED',
        category: 'SECURITY',
        severity: 'WARNING',
        details: {
          challengeId,
          userAnswer: answer,
          userId: challenge.userId,
          ipAddress: challenge.ipAddress
        },
        ipAddress: req ? req.ip : challenge.ipAddress,
        userAgent: req ? req.get('user-agent') : 'Unknown',
        resourceId: '/api/auth/verify-challenge',
        status: 'FAILURE',
        userId: challenge.userId
      });
      
      return {
        success: false,
        message: 'Challenge has expired',
        code: 'CHALLENGE_EXPIRED'
      };
    }
    
    // Check if challenge is already completed
    if (challenge.isCorrect !== null) {
      return {
        success: false,
        message: 'Challenge already completed',
        code: 'CHALLENGE_COMPLETED'
      };
    }
    
    // Verify the answer
    const isCorrect = answer.toString().toLowerCase() === challenge.correctAnswer.toLowerCase();
    
    // Update challenge with the result
    await Challenge.update(
      {
        userAnswer: answer,
        isCorrect,
        completedAt: new Date()
      },
      { where: { id: challengeId } }
    );
    
    // Log the verification attempt
    await logActivity({
      action: isCorrect ? 'CHALLENGE_SUCCESS' : 'CHALLENGE_FAILURE',
      category: 'SECURITY',
      severity: isCorrect ? 'INFO' : 'WARNING',
      details: {
        challengeId,
        challengeType: challenge.challengeType,
        userAnswer: answer,
        isCorrect,
        userId: challenge.userId,
        ipAddress: challenge.ipAddress
      },
      ipAddress: req ? req.ip : challenge.ipAddress,
      userAgent: req ? req.get('user-agent') : 'Unknown',
      resourceId: '/api/auth/verify-challenge',
      status: isCorrect ? 'SUCCESS' : 'FAILURE',
      userId: challenge.userId
    });
    
    if (isCorrect) {
      console.log(`✅ Challenge ${challengeId} solved correctly`);
      // Reset failed attempts for this IP/user (optional)
      // This allows the user to try logging in again
      return {
        success: true,
        message: 'Challenge solved correctly',
        challengeId
      };
    } else {
      console.log(`❌ Challenge ${challengeId} solved incorrectly`);
      return {
        success: false,
        message: 'Incorrect answer',
        code: 'INCORRECT_ANSWER'
      };
    }
  } catch (error) {
    console.error('❌ Error verifying challenge:', error);
    throw error;
  }
};

/**
 * Clean up expired challenges
 * @returns {Promise<number>} Number of deleted challenges
 */
const cleanupExpiredChallenges = async () => {
  try {
    console.log('🧹 Cleaning up expired challenges');
    
    const result = await Challenge.destroy({
      where: {
        expiresAt: {
          [Op.lt]: new Date()
        }
      }
    });
    
    console.log(`✅ Deleted ${result} expired challenges`);
    return result;
  } catch (error) {
    console.error('❌ Error cleaning up challenges:', error);
    throw error;
  }
};

/**
 * Get challenge statistics
 * @returns {Promise<Object>} Challenge statistics
 */
const getChallengeStats = async () => {
  try {
    const total = await Challenge.count();
    const solved = await Challenge.count({ where: { isCorrect: true } });
    const failed = await Challenge.count({ where: { isCorrect: false } });
    const pending = await Challenge.count({ 
      where: { 
        isCorrect: null,
        expiresAt: { [Op.gt]: new Date() }
      } 
    });
    
    return {
      total,
      solved,
      failed,
      pending,
      successRate: total > 0 ? (solved / total * 100).toFixed(2) + '%' : '0%'
    };
  } catch (error) {
    console.error('❌ Error getting challenge stats:', error);
    throw error;
  }
};

module.exports = {
  needsChallenge,
  createChallenge,
  verifyChallenge,
  cleanupExpiredChallenges,
  getChallengeStats,
  FAILED_ATTEMPTS_THRESHOLD,
  CHALLENGE_EXPIRY_MINUTES
};