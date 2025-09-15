/**
 * KiroSpecGuard Integration
 * Simulates Kiro IDE hook functionality for demo purposes
 */

import { XSSScanner } from './scanner/xss-scanner.js';
import { DocsGenerator } from './scanner/docs-generator.js';

export class KiroIntegration {
  constructor() {
    this.scanner = new XSSScanner();
    this.docsGenerator = new DocsGenerator();
    this.specifications = [
      "Prevent basic XSS vulnerabilities in all user input handling",
      "Ensure all user input is sanitized before rendering to HTML", 
      "Block direct DOM manipulation with untrusted data",
      "Follow OWASP Top 10 security practices"
    ];
    this.securityLog = [];
    this.isActive = false;
  }

  // Simulate Kiro IDE initialization
  initialize() {
    this.isActive = true;
    this.logSecurityEvent('INIT', 'KiroSpecGuard initialized with security specifications');
    this.logSecurityEvent('HOOK', 'File save hook registered successfully');
    this.logSecurityEvent('READY', 'Security monitoring active');
    
    return {
      status: 'initialized',
      specifications: this.specifications,
      timestamp: new Date().toISOString()
    };
  }

  // Simulate file save event (for demo)
  simulateFileSave(filename, content) {
    if (!this.isActive) {
      throw new Error('KiroSpecGuard not initialized');
    }

    this.logSecurityEvent('FILE_SAVE', `Scanning file: ${filename}`);
    
    const scanResult = this.scanner.scanFile(content, filename);
    
    if (scanResult.vulnerabilityCount > 0) {
      this.logSecurityEvent('VULNERABILITY_DETECTED', 
        `${scanResult.vulnerabilityCount} vulnerabilities found in ${filename}`);
      
      // Generate compliance documentation
      const complianceReport = this.docsGenerator.generateComplianceReport([scanResult], this.specifications);
      const savedReport = this.docsGenerator.saveReport(complianceReport, this.docsGenerator.generateReportId());
      
      this.logSecurityEvent('COMPLIANCE_DOC', `Generated report: ${savedReport.filename}`);
    } else {
      this.logSecurityEvent('SCAN_CLEAN', `No vulnerabilities found in ${filename}`);
    }

    return {
      scanResult,
      securityAlert: this.generateSecurityAlert(scanResult),
      timestamp: new Date().toISOString()
    };
  }

  generateSecurityAlert(scanResult) {
    if (scanResult.vulnerabilityCount === 0) {
      return {
        type: 'SUCCESS',
        title: '✅ Security Scan Passed',
        message: 'No security vulnerabilities detected',
        severity: 'LOW',
        color: 'success'
      };
    }

    const criticalCount = scanResult.vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const highCount = scanResult.vulnerabilities.filter(v => v.severity === 'HIGH').length;

    if (criticalCount > 0) {
      return {
        type: 'CRITICAL',
        title: '🚨 Critical Security Issues Detected',
        message: `${criticalCount} critical vulnerabilities require immediate attention`,
        severity: 'CRITICAL',
        color: 'destructive',
        details: scanResult.vulnerabilities.filter(v => v.severity === 'CRITICAL')
      };
    }

    if (highCount > 0) {
      return {
        type: 'HIGH',
        title: '⚠️ High Priority Security Issues',
        message: `${highCount} high-severity vulnerabilities found`,
        severity: 'HIGH', 
        color: 'warning',
        details: scanResult.vulnerabilities.filter(v => v.severity === 'HIGH')
      };
    }

    return {
      type: 'MEDIUM',
      title: '⚡ Security Issues Detected',
      message: `${scanResult.vulnerabilityCount} vulnerabilities need attention`,
      severity: 'MEDIUM',
      color: 'info',
      details: scanResult.vulnerabilities
    };
  }

  logSecurityEvent(type, message) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      type,
      message
    };
    
    this.securityLog.push(logEntry);
    
    // Simulate writing to .kiro/steering/security_decisions.log
    return `${logEntry.timestamp} [${type}] ${message}`;
  }

  getSecurityLog() {
    return this.securityLog;
  }

  getFormattedLog() {
    return this.securityLog.map(entry => 
      `${entry.timestamp} [${entry.type}] ${entry.message}`
    ).join('\n');
  }

  // Demo helper methods
  getDemoVulnerableFile() {
    return {
      filename: 'src/index.html',
      content: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable Demo</title>
</head>
<body>
    <h1>User Input Demo</h1>
    
    <!-- VULNERABLE CODE EXAMPLE -->
    <div id="user-content"></div>
    <script>
        // ❌ DANGEROUS: Direct innerHTML assignment with URL parameter
        const urlParams = new URLSearchParams(window.location.search);
        const userContent = urlParams.get('content');
        document.getElementById('user-content').innerHTML = userContent;
        
        // ❌ DANGEROUS: document.write with user input
        document.write('<p>Welcome: ' + userContent + '</p>');
        
        // ❌ DANGEROUS: eval with user input
        const userScript = urlParams.get('script');
        if (userScript) {
            eval(userScript);
        }
    </script>
    
    <!-- SECURE CODE EXAMPLE -->
    <div id="safe-content"></div>
    <script>
        // ✅ SAFE: Sanitized content
        function displaySafeContent(content) {
            const safeDiv = document.getElementById('safe-content');
            safeDiv.textContent = content; // Uses textContent, not innerHTML
        }
        
        // ✅ SAFE: Input validation and sanitization
        function sanitizeInput(input) {
            const div = document.createElement('div');
            div.textContent = input;
            return div.innerHTML;
        }
    </script>
</body>
</html>`
    };
  }

  runDemo() {
    console.log('🚀 KiroSpecGuard Demo Starting...\n');
    
    // Step 1: Initialize
    console.log('1. Initializing KiroSpecGuard...');
    const initResult = this.initialize();
    console.log(`✅ Status: ${initResult.status}`);
    console.log(`📋 Loaded ${initResult.specifications.length} security specifications\n`);
    
    // Step 2: Show specifications
    console.log('2. Security Specifications:');
    initResult.specifications.forEach((spec, index) => {
      console.log(`   ${index + 1}. ${spec}`);
    });
    console.log('');
    
    // Step 3: Simulate file save
    console.log('3. Simulating file save event...');
    const demoFile = this.getDemoVulnerableFile();
    console.log(`📁 File: ${demoFile.filename}`);
    
    const scanResult = this.simulateFileSave(demoFile.filename, demoFile.content);
    
    // Step 4: Show security alert
    console.log('4. Security Scan Results:');
    console.log(`🔍 Vulnerabilities Found: ${scanResult.scanResult.vulnerabilityCount}`);
    console.log(`⚠️  Risk Level: ${scanResult.scanResult.riskLevel}`);
    console.log(`📊 Alert: ${scanResult.securityAlert.title}`);
    console.log(`💬 Message: ${scanResult.securityAlert.message}\n`);
    
    // Step 5: Show vulnerability details
    if (scanResult.scanResult.vulnerabilities.length > 0) {
      console.log('5. Vulnerability Details:');
      scanResult.scanResult.vulnerabilities.forEach((vuln, index) => {
        console.log(`   ${index + 1}. Line ${vuln.line}: ${vuln.vulnerability}`);
        console.log(`      Description: ${vuln.description}`);
        console.log(`      Fix: ${vuln.suggestion}\n`);
      });
    }
    
    // Step 6: Show security log
    console.log('6. Security Decision Log:');
    this.getSecurityLog().slice(-5).forEach(entry => {
      console.log(`   ${entry.timestamp} [${entry.type}] ${entry.message}`);
    });
    
    console.log('\n🎯 Demo completed! KiroSpecGuard successfully detected and documented security issues.');
    
    return {
      demo: 'completed',
      results: scanResult,
      log: this.getFormattedLog()
    };
  }
}