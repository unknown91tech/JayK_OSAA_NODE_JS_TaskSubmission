/**
 * Monitor Failed Login Attempts Script
 * 
 * This script checks for suspicious login activity and sends alerts
 * via Telegram if suspicious patterns are detected.
 * 
 * It can be run as a cron job or scheduled task.
 */

const { ActivityLog } = require('../models');
const { Op } = require('sequelize');
const { sendAdminAlert } = require('../services/telegramService');
const { sequelize } = require('../config/db');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

// Find suspicious login attempts
const monitorFailedLogins = async () => {
  try {
    console.log('🔍 Monitoring for suspicious login activities...');
    
    // Initialize database connection
    await sequelize.authenticate();
    console.log('✅ Database connection established');
    
    // Get timestamp for 1 hour ago
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    
    // Find users with multiple failed login attempts in the last hour
    const suspiciousActivity = await ActivityLog.findAll({
      attributes: [
        'userId', 
        'ipAddress',
        [sequelize.fn('COUNT', sequelize.col('id')), 'failureCount']
      ],
      where: {
        action: 'LOGIN',
        status: 'FAILURE',
        createdAt: {
          [Op.gte]: oneHourAgo
        }
      },
      group: ['userId', 'ipAddress'],
      having: sequelize.literal('COUNT(id) >= 5'),
      raw: true
    });
    
    if (suspiciousActivity.length === 0) {
      console.log('✅ No suspicious login activity detected');
      return { success: true, alerts: 0 };
    }
    
    console.log(`⚠️ Found ${suspiciousActivity.length} instances of suspicious login activity`);
    
    // For each suspicious activity, get user details and send alert
    let alertsSent = 0;
    for (const activity of suspiciousActivity) {
      // Get user details
      const userDetails = await sequelize.query(
        'SELECT username, registrationMethod FROM "Users" WHERE id = :userId',
        {
          replacements: { userId: activity.userId },
          type: sequelize.QueryTypes.SELECT
        }
      );
      
      if (userDetails.length === 0) continue;
      
      const user = userDetails[0];
      
      // Prepare alert message
      const alertMessage = `🚨 SECURITY ALERT: Multiple failed login attempts detected\n\n` +
        `User: ${user.username}\n` +
        `IP Address: ${activity.ipAddress}\n` +
        `Failed Attempts: ${activity.failureCount}\n` +
        `Time Period: Last hour\n\n` +
        `The account may be under a brute force attack. Consider taking action.`;
      
      // Send alert via Telegram
      const alertResult = await sendAdminAlert(alertMessage);
      
      if (alertResult) {
        alertsSent++;
        console.log(`✅ Sent alert for user ${user.username}`);
      } else {
        console.error(`❌ Failed to send alert for user ${user.username}`);
      }
      
      // Log the security alert
      await ActivityLog.create({
        action: 'SECURITY_ALERT_SENT',
        category: 'SECURITY',
        severity: 'ALERT',
        details: {
          userId: activity.userId,
          username: user.username,
          ipAddress: activity.ipAddress,
          failedAttempts: activity.failureCount,
          alertSent: !!alertResult
        },
        ipAddress: '127.0.0.1',
        userAgent: 'System/MonitorScript',
        resourceId: 'login-monitor',
        status: 'SUCCESS',
        userId: activity.userId
      });
    }
    
    return { 
      success: true, 
      suspiciousActivities: suspiciousActivity.length,
      alertsSent 
    };
  } catch (error) {
    console.error('❌ Error monitoring failed logins:', error);
    return { success: false, error: error.message };
  } finally {
    // Close database connection
    await sequelize.close();
  }
};

// Run the monitor function if called directly
if (require.main === module) {
  monitorFailedLogins().then(result => {
    console.log('Monitoring completed with result:', result);
    process.exit(0);
  }).catch(error => {
    console.error('Monitoring failed:', error);
    process.exit(1);
  });
}

module.exports = { monitorFailedLogins };