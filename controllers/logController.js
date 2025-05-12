const { ActivityLog } = require('../models');
const { Op } = require('sequelize');
const { verifyAllLogFiles } = require('../tools/verifyLogs');
const { performIntegrityCheck } = require('../services/loggerService');
const path = require('path');
const fs = require('fs').promises;
require('dotenv').config();

// Define log file paths
const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, '../logs');

/**
 * Get activity logs with filtering and pagination
 */
const getActivityLogs = async (req, res) => {
  try {
    console.log('📋 Fetching activity logs with filters');
    
    // Parse query parameters
    const {
      page = 1,
      limit = 50,
      startDate,
      endDate,
      userId,
      action,
      category,
      severity,
      status,
      ipAddress,
      sortBy = 'createdAt',
      sortOrder = 'DESC'
    } = req.query;
    
    // Build filters
    const filters = {};
    
    if (startDate || endDate) {
      filters.createdAt = {};
      
      if (startDate) {
        filters.createdAt[Op.gte] = new Date(startDate);
      }
      
      if (endDate) {
        filters.createdAt[Op.lte] = new Date(endDate);
      }
    }
    
    if (userId) filters.userId = userId;
    if (action) filters.action = { [Op.like]: `%${action}%` };
    if (category) filters.category = category;
    if (severity) filters.severity = severity;
    if (status) filters.status = status;
    if (ipAddress) filters.ipAddress = ipAddress;
    
    // Calculate offset
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    // Query the logs
    const { count, rows } = await ActivityLog.findAndCountAll({
      where: filters,
      order: [[sortBy, sortOrder]],
      limit: parseInt(limit),
      offset: offset
    });
    
    // Calculate total pages
    const totalPages = Math.ceil(count / parseInt(limit));
    
    res.status(200).json({
      success: true,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        totalItems: count,
        totalPages
      },
      logs: rows
    });
  } catch (error) {
    console.error('❌ Error fetching activity logs:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while fetching activity logs'
    });
  }
};

/**
 * Get activity log categories and actions for filtering
 */
const getLogMetadata = async (req, res) => {
  try {
    console.log('🔍 Fetching log metadata for filters');
    
    // Get distinct actions
    const actions = await ActivityLog.findAll({
      attributes: [[sequelize.fn('DISTINCT', sequelize.col('action')), 'action']],
      raw: true
    });
    
    // Get distinct categories
    const categories = await ActivityLog.findAll({
      attributes: [[sequelize.fn('DISTINCT', sequelize.col('category')), 'category']],
      raw: true
    });
    
    // Get distinct severities
    const severities = await ActivityLog.findAll({
      attributes: [[sequelize.fn('DISTINCT', sequelize.col('severity')), 'severity']],
      raw: true
    });
    
    // Get distinct statuses
    const statuses = await ActivityLog.findAll({
      attributes: [[sequelize.fn('DISTINCT', sequelize.col('status')), 'status']],
      raw: true
    });
    
    res.status(200).json({
      success: true,
      metadata: {
        actions: actions.map(a => a.action),
        categories: categories.map(c => c.category),
        severities: severities.map(s => s.severity),
        statuses: statuses.map(s => s.status)
      }
    });
  } catch (error) {
    console.error('❌ Error fetching log metadata:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while fetching log metadata'
    });
  }
};

/**
 * Get user activity summary
 */
const getUserActivitySummary = async (req, res) => {
  try {
    const { userId } = req.params;
    console.log(`📊 Generating activity summary for user: ${userId}`);
    
    // Get all activity for this user
    const logs = await ActivityLog.findAll({
      where: { userId },
      order: [['createdAt', 'DESC']]
    });
    
    // Group logs by category
    const categorySummary = {};
    logs.forEach(log => {
      if (!categorySummary[log.category]) {
        categorySummary[log.category] = {
          count: 0,
          actions: {}
        };
      }
      
      categorySummary[log.category].count += 1;
      
      if (!categorySummary[log.category].actions[log.action]) {
        categorySummary[log.category].actions[log.action] = 0;
      }
      
      categorySummary[log.category].actions[log.action] += 1;
    });
    
    // Calculate login success/failure rates
    const loginAttempts = logs.filter(log => log.action === 'LOGIN');
    const successfulLogins = loginAttempts.filter(log => log.status === 'SUCCESS');
    const failedLogins = loginAttempts.filter(log => log.status === 'FAILURE');
    
    const loginSuccessRate = loginAttempts.length > 0 
      ? (successfulLogins.length / loginAttempts.length) * 100 
      : 0;
    
    // Get last 5 activities
    const recentActivity = logs.slice(0, 5);
    
    res.status(200).json({
      success: true,
      userId,
      summary: {
        totalEvents: logs.length,
        categorySummary,
        loginStats: {
          totalAttempts: loginAttempts.length,
          successful: successfulLogins.length,
          failed: failedLogins.length,
          successRate: loginSuccessRate.toFixed(2) + '%'
        },
        recentActivity
      }
    });
  } catch (error) {
    console.error('❌ Error generating user activity summary:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while generating activity summary'
    });
  }
};

/**
 * Get security alerts
 */
const getSecurityAlerts = async (req, res) => {
  try {
    console.log('🚨 Fetching security alerts');
    
    // Get all security alerts (high severity events)
    const alerts = await ActivityLog.findAll({
      where: {
        [Op.or]: [
          { severity: 'ALERT' },
          { severity: 'WARNING', category: 'SECURITY' }
        ]
      },
      order: [['createdAt', 'DESC']],
      limit: 100 // Limit to most recent 100 alerts
    });
    
    // Group alerts by type
    const alertTypes = {};
    alerts.forEach(alert => {
      if (!alertTypes[alert.action]) {
        alertTypes[alert.action] = 0;
      }
      alertTypes[alert.action] += 1;
    });
    
    res.status(200).json({
      success: true,
      alerts,
      summary: {
        totalAlerts: alerts.length,
        alertTypes
      }
    });
  } catch (error) {
    console.error('❌ Error fetching security alerts:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while fetching security alerts'
    });
  }
};

/**
 * Run log integrity verification
 */
const verifyLogIntegrity = async (req, res) => {
  try {
    console.log('🔐 Running log integrity verification');
    
    // Verify file integrity
    const verificationResults = await verifyAllLogFiles();
    
    // Also run the scheduled integrity check
    const integrityCheckResults = await performIntegrityCheck();
    
    res.status(200).json({
      success: true,
      verificationResults,
      integrityCheckResults
    });
  } catch (error) {
    console.error('❌ Error verifying log integrity:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during log integrity verification'
    });
  }
};

/**
 * Get raw log file content (for downloading)
 */
const getRawLogFile = async (req, res) => {
  try {
    const { category, date } = req.params;
    console.log(`📄 Retrieving raw log file: ${category}_${date}.log`);
    
    // Validate parameters to prevent path traversal
    if (!category.match(/^[a-zA-Z]+$/) || !date.match(/^\d{4}-\d{2}-\d{2}$/)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid category or date format'
      });
    }
    
    const logFilePath = path.join(LOG_DIR, `${category.toLowerCase()}_${date}.log`);
    
    try {
      await fs.access(logFilePath);
    } catch (error) {
      return res.status(404).json({
        success: false,
        message: 'Log file not found'
      });
    }
    
    // Read the file
    const fileContent = await fs.readFile(logFilePath, 'utf8');
    
    // Send the file content
    res.status(200).json({
      success: true,
      fileContent,
      filename: `${category.toLowerCase()}_${date}.log`
    });
  } catch (error) {
    console.error('❌ Error retrieving raw log file:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while retrieving the log file'
    });
  }
};

/**
 * Get login activity statistics
 */
const getLoginStats = async (req, res) => {
  try {
    console.log('📊 Generating login statistics');
    
    // Parse query parameters
    const { startDate, endDate } = req.query;
    
    // Build date filter
    const dateFilter = {};
    if (startDate || endDate) {
      dateFilter.createdAt = {};
      
      if (startDate) {
        dateFilter.createdAt[Op.gte] = new Date(startDate);
      }
      
      if (endDate) {
        dateFilter.createdAt[Op.lte] = new Date(endDate);
      }
    }
    
    // Get login attempts
    const loginLogs = await ActivityLog.findAll({
      where: {
        action: 'LOGIN',
        ...dateFilter
      },
      order: [['createdAt', 'ASC']]
    });
    
    // Calculate success/failure stats
    const successfulLogins = loginLogs.filter(log => log.status === 'SUCCESS');
    const failedLogins = loginLogs.filter(log => log.status === 'FAILURE');
    
    // Group by day
    const loginsByDay = {};
    loginLogs.forEach(log => {
      const day = log.createdAt.toISOString().split('T')[0];
      
      if (!loginsByDay[day]) {
        loginsByDay[day] = {
          total: 0,
          successful: 0,
          failed: 0
        };
      }
      
      loginsByDay[day].total += 1;
      if (log.status === 'SUCCESS') {
        loginsByDay[day].successful += 1;
      } else {
        loginsByDay[day].failed += 1;
      }
    });
    
    // Convert to array for easier client-side graphing
    const dailyStats = Object.keys(loginsByDay).map(day => ({
      date: day,
      ...loginsByDay[day]
    }));
    
    // Group by IP address
    const loginsByIp = {};
    loginLogs.forEach(log => {
      if (!loginsByIp[log.ipAddress]) {
        loginsByIp[log.ipAddress] = {
          total: 0,
          successful: 0,
          failed: 0
        };
      }
      
      loginsByIp[log.ipAddress].total += 1;
      if (log.status === 'SUCCESS') {
        loginsByIp[log.ipAddress].successful += 1;
      } else {
        loginsByIp[log.ipAddress].failed += 1;
      }
    });
    
    // Find suspicious IPs (high failure rate)
    const suspiciousIps = Object.keys(loginsByIp)
      .filter(ip => 
        loginsByIp[ip].total >= 5 && 
        (loginsByIp[ip].failed / loginsByIp[ip].total) > 0.5
      )
      .map(ip => ({
        ipAddress: ip,
        ...loginsByIp[ip],
        failureRate: (loginsByIp[ip].failed / loginsByIp[ip].total * 100).toFixed(2) + '%'
      }));
    
    res.status(200).json({
      success: true,
      summary: {
        totalLogins: loginLogs.length,
        successfulLogins: successfulLogins.length,
        failedLogins: failedLogins.length,
        successRate: (loginLogs.length > 0 
          ? (successfulLogins.length / loginLogs.length * 100).toFixed(2) 
          : 0) + '%'
      },
      dailyStats,
      suspiciousIps,
      uniqueIpCount: Object.keys(loginsByIp).length
    });
  } catch (error) {
    console.error('❌ Error generating login statistics:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while generating login statistics'
    });
  }
};

module.exports = {
  getActivityLogs,
  getLogMetadata,
  getUserActivitySummary,
  getSecurityAlerts,
  verifyLogIntegrity,
  getRawLogFile,
  getLoginStats
};