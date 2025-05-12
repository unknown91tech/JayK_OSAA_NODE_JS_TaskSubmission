/**
 * Log Verification Tool
 * 
 * This tool verifies the integrity of log files by comparing their current hashes
 * with the previously stored hashes.
 * 
 * It can be run as a scheduled job or on-demand to check for any tampering.
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

// Define log file paths
const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, '../logs');
const INTEGRITY_DIR = path.join(LOG_DIR, 'integrity');

// Compute file hash for verification
const computeFileHash = async (filePath) => {
  try {
    const fileContent = await fs.readFile(filePath);
    return crypto.createHash('sha256').update(fileContent).digest('hex');
  } catch (error) {
    console.error(`❌ Failed to compute hash for ${filePath}:`, error);
    return null;
  }
};

// Verify a specific log file
const verifyLogFile = async (logFilePath, hashFilePath) => {
  try {
    // Check if files exist
    try {
      await fs.access(logFilePath);
      await fs.access(hashFilePath);
    } catch {
      console.warn(`⚠️ Log or integrity file not found: ${path.basename(logFilePath)}`);
      return { 
        logFile: path.basename(logFilePath),
        valid: false, 
        reason: 'FILE_NOT_FOUND' 
      };
    }
    
    // Compute current hash
    const currentHash = await computeFileHash(logFilePath);
    
    // Read stored hash
    const storedHash = await fs.readFile(hashFilePath, 'utf8');
    
    const isValid = currentHash === storedHash;
    
    return { 
      logFile: path.basename(logFilePath),
      valid: isValid, 
      reason: isValid ? 'VALID' : 'HASH_MISMATCH',
      expected: storedHash,
      actual: currentHash
    };
  } catch (error) {
    console.error(`❌ Verification failed for ${logFilePath}:`, error);
    return { 
      logFile: path.basename(logFilePath),
      valid: false, 
      reason: 'VERIFICATION_ERROR',
      error: error.message
    };
  }
};

// List all log files and their integrity hashes
const listLogFiles = async () => {
  try {
    // Get all files in log directory
    const logFiles = await fs.readdir(LOG_DIR);
    const integrityFiles = await fs.readdir(INTEGRITY_DIR);
    
    // Filter actual log files
    const actualLogFiles = logFiles.filter(file => 
      file.endsWith('.log') && 
      !file.startsWith('.')
    );
    
    // Filter integrity files
    const actualIntegrityFiles = integrityFiles.filter(file => 
      file.endsWith('.hash') && 
      !file.startsWith('.')
    );
    
    console.log(`📊 Found ${actualLogFiles.length} log files and ${actualIntegrityFiles.length} integrity hashes\n`);
    
    // Match log files with their integrity hashes
    const matchedFiles = [];
    const unmatchedLogFiles = [];
    const unmatchedHashFiles = [];
    
    actualLogFiles.forEach(logFile => {
      const baseName = logFile.replace('.log', '');
      const matchingHashFile = actualIntegrityFiles.find(file => file.startsWith(baseName));
      
      if (matchingHashFile) {
        matchedFiles.push({
          logFile,
          hashFile: matchingHashFile
        });
      } else {
        unmatchedLogFiles.push(logFile);
      }
    });
    
    actualIntegrityFiles.forEach(hashFile => {
      const baseName = hashFile.replace('.hash', '');
      const matchingLogFile = actualLogFiles.find(file => file.startsWith(baseName));
      
      if (!matchingLogFile) {
        unmatchedHashFiles.push(hashFile);
      }
    });
    
    return {
      matchedFiles,
      unmatchedLogFiles,
      unmatchedHashFiles
    };
  } catch (error) {
    console.error('❌ Failed to list log files:', error);
    return {
      matchedFiles: [],
      unmatchedLogFiles: [],
      unmatchedHashFiles: []
    };
  }
};

// Verify all log files
const verifyAllLogFiles = async () => {
  try {
    console.log('🔍 Starting log file verification...\n');
    
    const { matchedFiles, unmatchedLogFiles, unmatchedHashFiles } = await listLogFiles();
    
    // Verify matched files
    const verificationResults = [];
    for (const { logFile, hashFile } of matchedFiles) {
      const logFilePath = path.join(LOG_DIR, logFile);
      const hashFilePath = path.join(INTEGRITY_DIR, hashFile);
      
      const result = await verifyLogFile(logFilePath, hashFilePath);
      verificationResults.push(result);
      
      // Print result immediately
      if (result.valid) {
        console.log(`✅ ${logFile}: VALID`);
      } else {
        console.log(`❌ ${logFile}: INVALID - ${result.reason}`);
      }
    }
    
    // Print unmatched files
    if (unmatchedLogFiles.length > 0) {
      console.log('\n⚠️ Log files without integrity hashes:');
      unmatchedLogFiles.forEach(file => console.log(`   - ${file}`));
    }
    
    if (unmatchedHashFiles.length > 0) {
      console.log('\n⚠️ Integrity hashes without log files:');
      unmatchedHashFiles.forEach(file => console.log(`   - ${file}`));
    }
    
    // Summary
    const validCount = verificationResults.filter(r => r.valid).length;
    const invalidCount = verificationResults.filter(r => !r.valid).length;
    
    console.log('\n📊 Verification Summary:');
    console.log(`   - Total files: ${matchedFiles.length}`);
    console.log(`   - Valid files: ${validCount}`);
    console.log(`   - Invalid files: ${invalidCount}`);
    console.log(`   - Unmatched log files: ${unmatchedLogFiles.length}`);
    console.log(`   - Unmatched hash files: ${unmatchedHashFiles.length}`);
    
    if (invalidCount > 0) {
      console.log('\n🚨 SECURITY ALERT: Log file tampering detected!');
      console.log('   The following files have been tampered with:');
      verificationResults
        .filter(r => !r.valid)
        .forEach(r => {
          console.log(`   - ${r.logFile} (${r.reason})`);
        });
    }
    
    return {
      success: true,
      validCount,
      invalidCount,
      unmatchedLogFilesCount: unmatchedLogFiles.length,
      unmatchedHashFilesCount: unmatchedHashFiles.length,
      results: verificationResults,
      unmatchedLogFiles,
      unmatchedHashFiles
    };
  } catch (error) {
    console.error('❌ Verification failed:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Run the verification if called directly
if (require.main === module) {
  verifyAllLogFiles().then(() => {
    console.log('\nVerification complete.');
  }).catch(error => {
    console.error('Verification failed:', error);
    process.exit(1);
  });
}

module.exports = {
  verifyLogFile,
  verifyAllLogFiles,
  listLogFiles,
  computeFileHash
};