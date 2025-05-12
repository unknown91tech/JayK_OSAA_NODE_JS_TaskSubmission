const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');
const { v4: uuidv4 } = require('uuid');

const Challenge = sequelize.define('Challenge', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: true, // Nullable for challenges before user identification
    references: {
      model: 'Users',
      key: 'id'
    }
  },
  ipAddress: {
    type: DataTypes.STRING,
    allowNull: false,
    comment: 'IP address that triggered the challenge'
  },
  challengeType: {
    type: DataTypes.ENUM('CAPTCHA', 'MATH_PROBLEM', 'SECURITY_QUESTION'),
    allowNull: false,
    defaultValue: 'CAPTCHA'
  },
  challengeData: {
    type: DataTypes.JSON,
    allowNull: false,
    comment: 'The challenge question/data'
  },
  correctAnswer: {
    type: DataTypes.STRING,
    allowNull: false,
    comment: 'The correct answer to the challenge'
  },
  userAnswer: {
    type: DataTypes.STRING,
    allowNull: true,
    comment: 'The answer provided by the user'
  },
  isCorrect: {
    type: DataTypes.BOOLEAN,
    allowNull: true,
    comment: 'Whether the challenge was solved correctly'
  },
  expiresAt: {
    type: DataTypes.DATE,
    allowNull: false,
    comment: 'When this challenge expires'
  },
  completedAt: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When the challenge was completed'
  },
  userAgent: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  sessionData: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Additional session information for verification'
  }
}, {
  timestamps: true,
  hooks: {
    beforeCreate: async (challenge) => {
      if (!challenge.id) {
        challenge.id = uuidv4();
      }
    }
  },
  indexes: [
    { fields: ['userId'] },
    { fields: ['ipAddress'] },
    { fields: ['expiresAt'] },
    { fields: ['challengeType'] }
  ]
});

module.exports = Challenge;