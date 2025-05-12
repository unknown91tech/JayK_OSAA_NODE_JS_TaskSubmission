const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { createWriteStream } = require('fs');
const util = require('util');
const ActivityLog = require('../models/ActivityLog');
require('dotenv').config();

// Define log file paths
const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, '../logs');
const INTEGRITY_DIR = path.join(LOG_DIR, 'integrity');
const LOG_ROTATION_SIZE = process.env.LOG_ROTATION_SIZE || 10 * 1024 * 1024; // 10MB default
const LOG_RETENTION_DAYS = process.env.LOG_RETENTION_DAYS || 90; // 90 days default

// Log file streams for different categories
const logStreams = {};
let currentLogFiles = {};

// Ensure directories exist
const initLogDirectories = async () => {
  try {
    await fs.mkdir(LOG_DIR, { recursive: true });
    await fs.mkdir(INTEGRITY_DIR, { recursive: true });
    console.log('✅ Log directories initialized');
  } catch (error) {
    console.error('❌ Failed to create log directories:', error);
  }
};

// Initialize log streams
const initLogStreams = () => {
  const categories = ['AUTH', 'MFA', 'ROLE', 'ACCESS', 'SECURITY', 'SYSTEM'];
  const date = new Date().toISOString().split('T')[0];
  
  categories.forEach(category => {
    const logFileName = `${category.toLowerCase()}_${date}.log`;
    const logFilePath = path.join(LOG_DIR, logFileName);
    
    currentLogFiles[category] = logFilePath;
    logStreams[category] = createWriteStream(logFilePath, { flags: 'a' });
    
    console.log(`📝 Initialized log stream for ${category}: ${logFileName}`);
  });
};

// Compute file hash for integrity verification
const computeFileHash = async (filePath) => {
  try {
    const fileContent = await fs.readFile(filePath);
    return crypto.createHash('sha256').update(fileContent).digest('hex');
  } catch (error) {
    console.error(`❌ Failed to compute hash for ${filePath}:`, error);
    return null;
  }
};

// Save integrity hashes
const saveIntegrityHash = async (category, date, hash) => {
  try {
    const integrityFilePath = path.join(INTEGRITY_DIR, `${category.toLowerCase()}_${date}.hash`);
    await fs.writeFile(integrityFilePath, hash);
    return true;
  } catch (error) {
    console.error(`❌ Failed to save integrity hash for ${category}:`, error);
    return false;
  }
};

// Verify file integrity
const verifyFileIntegrity = async (category, date) => {
  try {
    const logFileName = `${category.toLowerCase()}_${date}.log`;
    const logFilePath = path.join(LOG_DIR, logFileName);
    const integrityFilePath = path.join(INTEGRITY_DIR, `${category.toLowerCase()}_${date}.hash`);
    
    // Check if files exist
    try {
      await fs.access(logFilePath);
      await fs.access(integrityFilePath);
    } catch {
      console.warn(`⚠️ Log or integrity file not found for ${category} on ${date}`);
      return { valid: false, reason: 'FILES_NOT_FOUND' };
    }
    
    // Compute current hash
    const currentHash = await computeFileHash(logFilePath);
    
    // Read stored hash
    const storedHash = await fs.readFile(integrityFilePath, 'utf8');
    
    return { 
      valid: currentHash === storedHash, 
      reason: currentHash === storedHash ? 'VALID' : 'HASH_MISMATCH' 
    };
  } catch (error) {
    console.error(`❌ Integrity verification failed for ${category} on ${date}:`, error);
    return { valid: false, reason: 'VERIFICATION_ERROR' };
  }
};

// Check log file size and rotate if needed
const checkAndRotateLog = async (category) => {
  try {
    if (!currentLogFiles[category]) return;
    
    const filePath = currentLogFiles[category];
    const stats = await fs.stat(filePath);
    
    if (stats.size >= LOG_ROTATION_SIZE) {
      // Close current stream
      logStreams[category].end();
      
      // Generate new filename with timestamp
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const rotatedFilePath = `${filePath}.${timestamp}`;
      
      // Rename current file
      await fs.rename(filePath, rotatedFilePath);
      
      // Compute and save hash for rotated file
      const hash = await computeFileHash(rotatedFilePath);
      if (hash) {
        const datePart = filePath.split('_')[1].split('.')[0];
        await saveIntegrityHash(category, `${datePart}.${timestamp}`, hash);
      }
      
      // Create new stream
      const date = new Date().toISOString().split('T')[0];
      const newLogFileName = `${category.toLowerCase()}_${date}.log`;
      const newLogFilePath = path.join(LOG_DIR, newLogFileName);
      
      currentLogFiles[category] = newLogFilePath;
      logStreams[category] = createWriteStream(newLogFilePath, { flags: 'a' });
      
      console.log(`🔄 Rotated log file for ${category}: ${newLogFileName}`);
    }
  } catch (error) {
    console.error(`❌ Error checking/rotating log for ${category}:`, error);
  }
};

// Log to file
const logToFile = async (logEntry) => {
  try {
    if (!logStreams[logEntry.category]) {
      console.warn(`⚠️ No log stream for category ${logEntry.category}, initializing streams`);
      initLogStreams();
    }
    
    // Check if rotation is needed
    await checkAndRotateLog(logEntry.category);
    
    // Format log entry for file
    const formattedLog = JSON.stringify({
      timestamp: new Date().toISOString(),
      ...logEntry
    }) + '\n';
    
    // Write to file
    logStreams[logEntry.category].write(formattedLog);
    
    return true;
  } catch (error) {
    console.error('❌ Failed to write to log file:', error);
    return false;
  }
};

// Log to database and file
const logActivity = async (logEntry) => {
  try {
    // Compute hash of log entry for integrity
    const entryHash = crypto
      .createHash('sha256')
      .update(JSON.stringify(logEntry))
      .digest('hex');
    
    // Add hash to log entry
    logEntry.hashValue = entryHash;
    
    // Log to database
    const dbLog = await ActivityLog.create(logEntry);
    
    // Log to file
    await logToFile(logEntry);
    
    return dbLog;
  } catch (error) {
    console.error('❌ Failed to log activity:', error);
    
    // Attempt to log to file even if DB fails
    try {
      logEntry.dbFailure = true;
      await logToFile(logEntry);
    } catch {}
    
    return null;
  }
};

// Check for file tampering and save new integrity hashes
const performIntegrityCheck = async () => {
  try {
    const categories = ['AUTH', 'MFA', 'ROLE', 'ACCESS', 'SECURITY', 'SYSTEM'];
    const today = new Date().toISOString().split('T')[0];
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    
    // Check yesterday's logs
    let tamperedFiles = [];
    for (const category of categories) {
      const result = await verifyFileIntegrity(category, yesterday);
      if (!result.valid && result.reason !== 'FILES_NOT_FOUND') {
        tamperedFiles.push({
          category,
          date: yesterday,
          reason: result.reason
        });
      }
    }
    
    // Save today's hashes
    for (const category of categories) {
      const logFilePath = path.join(LOG_DIR, `${category.toLowerCase()}_${today}.log`);
      try {
        await fs.access(logFilePath);
        const hash = await computeFileHash(logFilePath);
        if (hash) {
          await saveIntegrityHash(category, today, hash);
        }
      } catch (error) {
        // File doesn't exist yet, which is okay
      }
    }
    
    // Log tampered files
    if (tamperedFiles.length > 0) {
      for (const file of tamperedFiles) {
        await logActivity({
          action: 'INTEGRITY_VIOLATION',
          category: 'SECURITY',
          severity: 'ALERT',
          details: file,
          ipAddress: '127.0.0.1',
          status: 'ALERT',
          resourceId: `${file.category.toLowerCase()}_${file.date}.log`
        });
      }
      
      console.error('🚨 SECURITY ALERT: Log file tampering detected:', tamperedFiles);
    }
    
    return {
      success: true,
      tamperedFiles
    };
  } catch (error) {
    console.error('❌ Failed to perform integrity check:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Delete old logs
const cleanupOldLogs = async () => {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - LOG_RETENTION_DAYS);
    
    // Get all files in log directories
    const logFiles = await fs.readdir(LOG_DIR);
    const integrityFiles = await fs.readdir(INTEGRITY_DIR);
    
    // Delete old log files
    for (const file of logFiles) {
      if (file === '.' || file === '..' || !file.includes('_')) continue;
      
      try {
        const filePath = path.join(LOG_DIR, file);
        const stats = await fs.stat(filePath);
        
        if (stats.isFile() && stats.mtime < cutoffDate) {
          await fs.unlink(filePath);
          console.log(`🗑️ Deleted old log file: ${file}`);
        }
      } catch (error) {
        console.error(`❌ Failed to delete old log file ${file}:`, error);
      }
    }
    
    // Delete old integrity files
    for (const file of integrityFiles) {
      if (file === '.' || file === '..' || !file.includes('_')) continue;
      
      try {
        const filePath = path.join(INTEGRITY_DIR, file);
        const stats = await fs.stat(filePath);
        
        if (stats.isFile() && stats.mtime < cutoffDate) {
          await fs.unlink(filePath);
          console.log(`🗑️ Deleted old integrity file: ${file}`);
        }
      } catch (error) {
        console.error(`❌ Failed to delete old integrity file ${file}:`, error);
      }
    }
    
    return true;
  } catch (error) {
    console.error('❌ Failed to clean up old logs:', error);
    return false;
  }
};

// Initialize logging system
const initLogging = async () => {
  await initLogDirectories();
  initLogStreams();
  
  // Schedule integrity check to run daily at midnight
  const scheduleIntegrityCheck = () => {
    const now = new Date();
    const midnight = new Date(
      now.getFullYear(),
      now.getMonth(),
      now.getDate() + 1,
      0, 0, 0
    );
    const msUntilMidnight = midnight - now;
    
    setTimeout(() => {
      performIntegrityCheck();
      cleanupOldLogs();
      scheduleIntegrityCheck(); // Reschedule for the next day
    }, msUntilMidnight);
    
    console.log(`📅 Scheduled integrity check and cleanup to run in ${Math.round(msUntilMidnight / 60000)} minutes`);
  };
  
  // Run initial integrity check and schedule next one
  await performIntegrityCheck();
  scheduleIntegrityCheck();
  
  return true;
};

// Helper function for detecting suspicious activity
const detectSuspiciousActivity = async (userId, action, threshold) => {
  try {
    const past15Minutes = new Date(Date.now() - 15 * 60 * 1000);
    
    const count = await ActivityLog.count({
      where: {
        userId,
        action,
        status: 'FAILURE',
        createdAt: {
          [require('sequelize').Op.gte]: past15Minutes
        }
      }
    });
    
    return count >= threshold;
  } catch (error) {
    console.error(`❌ Failed to detect suspicious activity for ${userId}:`, error);
    return false;
  }
};

module.exports = {
  initLogging,
  logActivity,
  performIntegrityCheck,
  verifyFileIntegrity,
  detectSuspiciousActivity
};