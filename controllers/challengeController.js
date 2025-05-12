const {
  needsChallenge,
  createChallenge,
  verifyChallenge,
  getChallengeStats
} = require('../services/challengeService');
const { User } = require('../models');

/**
 * Create a new challenge for a user
 */
const createUserChallenge = async (req, res) => {
  try {
    console.log('🧩 Processing challenge creation request');
    const { username } = req.body;
    const ipAddress = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
    
    let userId = null;
    
    // If username is provided, try to find the user
    if (username) {
      const user = await User.findOne({ where: { username } });
      if (user) {
        userId = user.id;
      }
    }
    
    // Check if challenge is needed
    const challengeNeeded = await needsChallenge(userId, ipAddress);
    
    if (!challengeNeeded) {
      return res.status(200).json({
        success: true,
        message: 'No challenge required',
        challengeRequired: false
      });
    }
    
    // Create challenge
    const challenge = await createChallenge(userId, ipAddress, req);
    
    res.status(200).json({
      success: true,
      message: 'Challenge created successfully',
      challengeRequired: true,
      challenge: {
        id: challenge.id,
        type: challenge.type,
        question: challenge.challenge.question,
        image: challenge.challenge.image, // ASCII art or base64 image
        expiresAt: challenge.expiresAt
      }
    });
  } catch (error) {
    console.error('❌ Challenge creation error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while creating challenge'
    });
  }
};

/**
 * Verify a challenge answer
 */
const verifyChallengeAnswer = async (req, res) => {
  try {
    console.log('🔍 Processing challenge verification');
    const { challengeId, answer } = req.body;
    
    if (!challengeId || !answer) {
      return res.status(400).json({
        success: false,
        message: 'Challenge ID and answer are required'
      });
    }
    
    // Verify the challenge
    const result = await verifyChallenge(challengeId, answer, req);
    
    if (result.success) {
      res.status(200).json({
        success: true,
        message: 'Challenge verified successfully',
        challengeId: result.challengeId
      });
    } else {
      res.status(400).json({
        success: false,
        message: result.message,
        code: result.code
      });
    }
  } catch (error) {
    console.error('❌ Challenge verification error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during challenge verification'
    });
  }
};

/**
 * Get challenge statistics (admin only)
 */
const getChallengeStatistics = async (req, res) => {
  try {
    console.log('📊 Fetching challenge statistics');
    
    const stats = await getChallengeStats();
    
    res.status(200).json({
      success: true,
      statistics: stats
    });
  } catch (error) {
    console.error('❌ Error fetching challenge statistics:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while fetching statistics'
    });
  }
};

/**
 * Check if challenge is required for login attempt
 */
const checkChallengeRequired = async (req, res) => {
  try {
    const { username } = req.query;
    const ipAddress = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
    
    let userId = null;
    
    // If username is provided, try to find the user
    if (username) {
      const user = await User.findOne({ where: { username } });
      if (user) {
        userId = user.id;
      }
    }
    
    // Check if challenge is needed
    const challengeNeeded = await needsChallenge(userId, ipAddress);
    
    res.status(200).json({
      success: true,
      challengeRequired: challengeNeeded,
      message: challengeNeeded 
        ? 'Challenge required due to multiple failed login attempts'
        : 'No challenge required'
    });
  } catch (error) {
    console.error('❌ Error checking challenge requirement:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while checking challenge requirement'
    });
  }
};

module.exports = {
  createUserChallenge,
  verifyChallengeAnswer,
  getChallengeStatistics,
  checkChallengeRequired
};