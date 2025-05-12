/**
 * Log Rotation and Archiving Script
 * 
 * This script rotates log files daily, compresses old logs,
 * and removes logs older than the retention period.
 * 
 * It can be run as a cron job (e.g., daily at midnight).
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { promisify } = require('util');
const { pipeline } = require('stream');
const { createReadStream, createWriteStream } = require('fs');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

// Promisify zlib functions
const gzip = promisify(zlib.gzip);
const pipelineAsync = promisify(pipeline);

// Define log file paths
const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, '../logs');
const ARCHIVE_DIR = path.join(LOG_DIR, 'archive');
const INTEGRITY_DIR = path.join(LOG_DIR, 'integrity');
const LOG_RETENTION_DAYS = parseInt(process.env.LOG_RETENTION_DAYS || '90', 10);

// Ensure directories exist
const initDirectories = async () => {
  try {
    await fs.mkdir(LOG_DIR, { recursive: true });
    await fs.mkdir(ARCHIVE_DIR, { recursive: true });
    await fs.mkdir(INTEGRITY_DIR, { recursive: true });
    console.log('✅ Directories initialized');
  } catch (error) {
    console.error('❌ Failed to create directories:', error);
    throw error;
  }
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

// Save integrity hash
const saveIntegrityHash = async (fileName, hash) => {
  try {
    const hashFileName = fileName.replace('.log', '.hash');
    const hashFilePath = path.join(INTEGRITY_DIR, hashFileName);
    await fs.writeFile(hashFilePath, hash);
    return true;
  } catch (error) {
    console.error(`❌ Failed to save integrity hash for ${fileName}:`, error);
    return false;
  }
};

// Compress a log file
const compressLogFile = async (logFilePath, archiveFilePath) => {
  try {
    await pipelineAsync(
      createReadStream(logFilePath),
      zlib.createGzip(),
      createWriteStream(archiveFilePath)
    );
    return true;
  } catch (error) {
    console.error(`❌ Failed to compress ${logFilePath}:`, error);
    return false;
  }
};

// Rotate current log files
const rotateCurrentLogs = async () => {
  try {
    const files = await fs.readdir(LOG_DIR);
    const currentDate = new Date().toISOString().split('T')[0];
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    
    // Filter for yesterday's log files
    const logFilesToRotate = files.filter(file => {
      return file.endsWith('.log') && file.includes(`_${yesterday}`);
    });
    
    console.log(`📋 Found ${logFilesToRotate.length} log files to rotate`);
    
    // Rotate each log file
    const rotationResults = [];
    for (const file of logFilesToRotate) {
      const logFilePath = path.join(LOG_DIR, file);
      const archiveFileName = `${file}.gz`;
      const archiveFilePath = path.join(ARCHIVE_DIR, archiveFileName);
      
      try {
        // Compute hash before compression
        const hash = await computeFileHash(logFilePath);
        if (!hash) {
          rotationResults.push({
            file,
            success: false,
            reason: 'Failed to compute hash'
          });
          continue;
        }
        
        // Save the hash value (move the integrity file to archive)
        const hashSaved = await saveIntegrityHash(archiveFileName, hash);
        if (!hashSaved) {
          rotationResults.push({
            file,
            success: false,
            reason: 'Failed to save integrity hash'
          });
          continue;
        }
        
        // Compress the log file
        const compressed = await compressLogFile(logFilePath, archiveFilePath);
        if (!compressed) {
          rotationResults.push({
            file,
            success: false,
            reason: 'Failed to compress file'
          });
          continue;
        }
        
        // Delete the original log file
        await fs.unlink(logFilePath);
        
        // Move the integrity file to archive
        const integrityFilePath = path.join(INTEGRITY_DIR, file.replace('.log', '.hash'));
        const archiveIntegrityFilePath = path.join(INTEGRITY_DIR, archiveFileName.replace('.gz', '.hash'));
        
        try {
          // Check if the integrity file exists
          await fs.access(integrityFilePath);
          
          // Rename/move the integrity file
          await fs.rename(integrityFilePath, archiveIntegrityFilePath);
        } catch (error) {
          console.warn(`⚠️ No integrity file found for ${file}, creating a new one`);
        }
        
        rotationResults.push({
          file,
          success: true,
          archiveFile: archiveFileName
        });
        
        console.log(`✅ Successfully rotated ${file} to ${archiveFileName}`);
      } catch (error) {
        console.error(`❌ Failed to rotate ${file}:`, error);
        rotationResults.push({
          file,
          success: false,
          reason: error.message
        });
      }
    }
    
    return {
      totalFiles: logFilesToRotate.length,
      successCount: rotationResults.filter(r => r.success).length,
      failureCount: rotationResults.filter(r => !r.success).length,
      results: rotationResults
    };
  } catch (error) {
    console.error('❌ Failed to rotate logs:', error);
    throw error;
  }
};

// Remove old log files beyond retention period
const removeOldLogs = async () => {
  try {
    const files = await fs.readdir(ARCHIVE_DIR);
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - LOG_RETENTION_DAYS);
    
    // Filter for log files older than retention period
    const oldLogFiles = [];
    const removalResults = [];
    
    for (const file of files) {
      if (!file.endsWith('.gz')) continue;
      
      // Extract date from filename
      const match = file.match(/\d{4}-\d{2}-\d{2}/);
      if (!match) continue;
      
      const fileDate = new Date(match[0]);
      if (fileDate < cutoffDate) {
        oldLogFiles.push(file);
      }
    }
    
    console.log(`🧹 Found ${oldLogFiles.length} old log files to remove`);
    
    // Remove each old log file
    for (const file of oldLogFiles) {
      try {
        const archiveFilePath = path.join(ARCHIVE_DIR, file);
        const hashFilePath = path.join(INTEGRITY_DIR, file.replace('.gz', '.hash'));
        
        // Delete the archive file
        await fs.unlink(archiveFilePath);
        
        // Delete the associated hash file if it exists
        try {
          await fs.access(hashFilePath);
          await fs.unlink(hashFilePath);
        } catch {
          // Hash file doesn't exist, which is fine
        }
        
        removalResults.push({
          file,
          success: true
        });
        
        console.log(`✅ Successfully removed old log file: ${file}`);
      } catch (error) {
        console.error(`❌ Failed to remove ${file}:`, error);
        removalResults.push({
          file,
          success: false,
          reason: error.message
        });
      }
    }
    
    return {
      totalFiles: oldLogFiles.length,
      successCount: removalResults.filter(r => r.success).length,
      failureCount: removalResults.filter(r => !r.success).length,
      results: removalResults
    };
  } catch (error) {
    console.error('❌ Failed to remove old logs:', error);
    throw error;
  }
};

// Main function
const rotateAndArchiveLogs = async () => {
  try {
    console.log('🔄 Starting log rotation and archiving...');
    
    // Initialize directories
    await initDirectories();
    
    // Rotate current logs
    const rotationResult = await rotateCurrentLogs();
    
    // Remove old logs
    const removalResult = await removeOldLogs();
    
    console.log('✅ Log rotation and archiving completed successfully');
    
    return {
      success: true,
      rotation: rotationResult,
      removal: removalResult
    };
  } catch (error) {
    console.error('❌ Log rotation and archiving failed:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Run the rotation script if called directly
if (require.main === module) {
  rotateAndArchiveLogs().then(result => {
    console.log('Script completed with result:', result);
    process.exit(0);
  }).catch(error => {
    console.error('Script failed:', error);
    process.exit(1);
  });
}

module.exports = { rotateAndArchiveLogs };