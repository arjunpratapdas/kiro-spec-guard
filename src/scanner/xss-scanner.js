/**
 * KiroSpecGuard XSS Scanner
 * Detects dangerous patterns and provides security recommendations
 */

export class XSSScanner {
  constructor() {
    this.dangerousPatterns = [
      {
        pattern: /\.innerHTML\s*=/gi,
        severity: 'HIGH',
        type: 'XSS_INNERHTML',
        description: 'Direct innerHTML assignment can lead to XSS vulnerabilities',
        suggestion: 'Use textContent or sanitize HTML with DOMPurify'
      },
      {
        pattern: /\.outerHTML\s*=/gi,
        severity: 'HIGH',
        type: 'XSS_OUTERHTML',
        description: 'Direct outerHTML assignment can lead to XSS vulnerabilities',
        suggestion: 'Use safe DOM manipulation methods or sanitize content'
      },
      {
        pattern: /document\.write\s*\(/gi,
        severity: 'CRITICAL',
        type: 'XSS_DOCUMENT_WRITE',
        description: 'document.write() can execute malicious scripts',
        suggestion: 'Use modern DOM manipulation methods like createElement'
      },
      {
        pattern: /eval\s*\(/gi,
        severity: 'CRITICAL',
        type: 'CODE_INJECTION',
        description: 'eval() can execute arbitrary code and is highly dangerous',
        suggestion: 'Use JSON.parse() for data or refactor to avoid eval'
      },
      {
        pattern: /dangerouslySetInnerHTML/gi,
        severity: 'MEDIUM',
        type: 'REACT_XSS',
        description: 'dangerouslySetInnerHTML can introduce XSS if not sanitized',
        suggestion: 'Sanitize HTML content with DOMPurify before use'
      }
    ];
  }

  scanFile(content, filename) {
    const vulnerabilities = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      this.dangerousPatterns.forEach(pattern => {
        const matches = line.match(pattern.pattern);
        if (matches) {
          vulnerabilities.push({
            filename,
            line: index + 1,
            code: line.trim(),
            vulnerability: pattern.type,
            severity: pattern.severity,
            description: pattern.description,
            suggestion: pattern.suggestion,
            timestamp: new Date().toISOString()
          });
        }
      });
    });

    return {
      filename,
      scanTime: new Date().toISOString(),
      vulnerabilityCount: vulnerabilities.length,
      vulnerabilities,
      riskLevel: this.calculateRiskLevel(vulnerabilities)
    };
  }

  calculateRiskLevel(vulnerabilities) {
    if (vulnerabilities.some(v => v.severity === 'CRITICAL')) return 'CRITICAL';
    if (vulnerabilities.some(v => v.severity === 'HIGH')) return 'HIGH';
    if (vulnerabilities.some(v => v.severity === 'MEDIUM')) return 'MEDIUM';
    return 'LOW';
  }

  generateSecurityReport(scanResults) {
    return {
      summary: {
        totalFiles: scanResults.length,
        totalVulnerabilities: scanResults.reduce((acc, result) => acc + result.vulnerabilityCount, 0),
        riskLevel: this.calculateOverallRisk(scanResults)
      },
      details: scanResults,
      recommendations: this.generateRecommendations(scanResults)
    };
  }

  calculateOverallRisk(scanResults) {
    const allVulns = scanResults.flatMap(result => result.vulnerabilities);
    return this.calculateRiskLevel(allVulns);
  }

  generateRecommendations(scanResults) {
    const recommendations = [
      'Implement input sanitization for all user data',
      'Use Content Security Policy (CSP) headers',
      'Regular security code reviews',
      'Automated security testing in CI/CD pipeline'
    ];

    return recommendations;
  }
}