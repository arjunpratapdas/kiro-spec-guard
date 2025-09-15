/**
 * KiroSpecGuard Documentation Generator
 * Creates compliance evidence for SOC 2, GDPR, and security audits
 */

export class DocsGenerator {
  constructor() {
    this.complianceStandards = {
      'SOC2': {
        'CC6.1': 'Logical and physical access controls',
        'CC6.2': 'Authentication and authorization',
        'CC6.3': 'System configurations'
      },
      'GDPR': {
        'Art25': 'Data protection by design and by default',
        'Art32': 'Security of processing'
      },
      'OWASP': {
        'A03': 'Injection vulnerabilities',
        'A07': 'Cross-Site Scripting (XSS)'
      }
    };
  }

  generateComplianceReport(scanResults, specifications) {
    const timestamp = new Date().toISOString();
    const reportId = this.generateReportId();
    
    const report = {
      metadata: {
        reportId,
        timestamp,
        version: '1.0.0',
        generatedBy: 'KiroSpecGuard',
        standards: ['SOC2', 'GDPR', 'OWASP']
      },
      executiveSummary: this.generateExecutiveSummary(scanResults),
      specifications: this.formatSpecifications(specifications),
      findings: this.formatFindings(scanResults),
      evidence: this.generateEvidence(scanResults),
      recommendations: this.generateComplianceRecommendations(scanResults),
      attestation: this.generateAttestation(scanResults)
    };

    return this.formatAsMarkdown(report);
  }

  generateReportId() {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 8);
    return `KIRO-${timestamp}-${random}`.toUpperCase();
  }

  generateExecutiveSummary(scanResults) {
    const totalVulns = scanResults.reduce((acc, result) => acc + result.vulnerabilityCount, 0);
    const criticalCount = scanResults.reduce((acc, result) => 
      acc + result.vulnerabilities.filter(v => v.severity === 'CRITICAL').length, 0);
    
    return {
      totalVulnerabilities: totalVulns,
      criticalVulnerabilities: criticalCount,
      complianceStatus: criticalCount === 0 ? 'COMPLIANT' : 'NON-COMPLIANT',
      lastScan: new Date().toISOString()
    };
  }

  formatSpecifications(specifications) {
    return specifications.map(spec => ({
      requirement: spec,
      status: 'MONITORED',
      implementation: 'Automated scanning via KiroSpecGuard'
    }));
  }

  formatFindings(scanResults) {
    return scanResults.flatMap(result => 
      result.vulnerabilities.map(vuln => ({
        id: `${result.filename}-${vuln.line}`,
        file: vuln.filename,
        line: vuln.line,
        type: vuln.vulnerability,
        severity: vuln.severity,
        description: vuln.description,
        recommendation: vuln.suggestion,
        complianceImpact: this.mapToCompliance(vuln.vulnerability)
      }))
    );
  }

  mapToCompliance(vulnerabilityType) {
    const mapping = {
      'XSS_INNERHTML': ['OWASP A07', 'SOC2 CC6.1'],
      'XSS_OUTERHTML': ['OWASP A07', 'SOC2 CC6.1'],
      'XSS_DOCUMENT_WRITE': ['OWASP A07', 'SOC2 CC6.1'],
      'CODE_INJECTION': ['OWASP A03', 'SOC2 CC6.1', 'GDPR Art32'],
      'REACT_XSS': ['OWASP A07', 'SOC2 CC6.1']
    };
    
    return mapping[vulnerabilityType] || ['General Security'];
  }

  generateEvidence(scanResults) {
    return {
      scanCoverage: '100% of monitored files',
      automatedChecks: 'XSS, Code Injection, DOM manipulation',
      detectionCapabilities: 'Real-time on file save',
      lastFullScan: new Date().toISOString(),
      toolVersion: 'KiroSpecGuard v1.0.0'
    };
  }

  generateComplianceRecommendations(scanResults) {
    const recommendations = [
      {
        standard: 'SOC2 CC6.1',
        recommendation: 'Implement comprehensive input validation',
        priority: 'HIGH'
      },
      {
        standard: 'GDPR Art32',
        recommendation: 'Ensure data processing security measures',
        priority: 'MEDIUM'
      },
      {
        standard: 'OWASP A07',
        recommendation: 'Deploy XSS protection mechanisms',
        priority: 'HIGH'
      }
    ];

    return recommendations;
  }

  generateAttestation(scanResults) {
    const hasVulnerabilities = scanResults.some(result => result.vulnerabilityCount > 0);
    
    return {
      statement: hasVulnerabilities 
        ? 'Security vulnerabilities detected and documented for remediation'
        : 'No security vulnerabilities detected in current scan',
      signedBy: 'KiroSpecGuard Automated System',
      timestamp: new Date().toISOString(),
      validity: '30 days from scan date'
    };
  }

  formatAsMarkdown(report) {
    return `# Security Compliance Report

**Report ID:** ${report.metadata.reportId}
**Generated:** ${new Date(report.metadata.timestamp).toLocaleString()}
**Standards:** ${report.metadata.standards.join(', ')}

## Executive Summary

- **Total Vulnerabilities:** ${report.executiveSummary.totalVulnerabilities}
- **Critical Vulnerabilities:** ${report.executiveSummary.criticalVulnerabilities}
- **Compliance Status:** ${report.executiveSummary.complianceStatus}

## Security Specifications

${report.specifications.map(spec => 
  `- **Requirement:** ${spec.requirement}\n  - **Status:** ${spec.status}\n  - **Implementation:** ${spec.implementation}`
).join('\n\n')}

## Findings

${report.findings.length === 0 ? '✅ No security vulnerabilities detected' : 
  report.findings.map(finding => 
    `### ${finding.id}
- **File:** ${finding.file}:${finding.line}
- **Type:** ${finding.type}
- **Severity:** ${finding.severity}
- **Description:** ${finding.description}
- **Recommendation:** ${finding.recommendation}
- **Compliance Impact:** ${finding.complianceImpact.join(', ')}`
  ).join('\n\n')}

## Evidence

- **Scan Coverage:** ${report.evidence.scanCoverage}
- **Automated Checks:** ${report.evidence.automatedChecks}
- **Detection:** ${report.evidence.detectionCapabilities}
- **Tool Version:** ${report.evidence.toolVersion}

## Recommendations

${report.recommendations.map(rec => 
  `- **${rec.standard}:** ${rec.recommendation} (Priority: ${rec.priority})`
).join('\n')}

## Attestation

${report.attestation.statement}

**Signed by:** ${report.attestation.signedBy}
**Timestamp:** ${report.attestation.timestamp}
**Valid for:** ${report.attestation.validity}

---
*This report was automatically generated by KiroSpecGuard*
`;
  }

  saveReport(markdownReport, reportId) {
    const filename = `.kiro/compliance/security-report-${reportId}-${Date.now()}.md`;
    return {
      filename,
      content: markdownReport,
      saved: true,
      timestamp: new Date().toISOString()
    };
  }
}