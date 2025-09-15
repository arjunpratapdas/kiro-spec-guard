import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Shield, FileText, AlertTriangle, CheckCircle, Play, Code, Settings } from 'lucide-react';

interface Vulnerability {
  filename: string;
  line: number;
  code: string;
  vulnerability: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  suggestion: string;
  timestamp: string;
}

interface ScanResult {
  filename: string;
  scanTime: string;
  vulnerabilityCount: number;
  vulnerabilities: Vulnerability[];
  riskLevel: string;
}

interface SecurityAlert {
  type: string;
  title: string;
  message: string;
  severity: string;
  color: string;
  details?: Vulnerability[];
}

const SecurityDashboard = () => {
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [securityAlert, setSecurityAlert] = useState<SecurityAlert | null>(null);
  const [securityLog, setSecurityLog] = useState<string[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [selectedFile, setSelectedFile] = useState<string>('');

  const specifications = [
    "Prevent basic XSS vulnerabilities in all user input handling",
    "Ensure all user input is sanitized before rendering to HTML",
    "Block direct DOM manipulation with untrusted data",
    "Follow OWASP Top 10 security practices"
  ];

  const demoFiles = {
    'vulnerable-demo.html': `<!DOCTYPE html>
<html>
<head><title>Vulnerable Demo</title></head>
<body>
<script>
// ❌ CRITICAL: Direct innerHTML with user input
const userInput = new URLSearchParams(window.location.search).get('content');
document.getElementById('output').innerHTML = userInput;

// ❌ CRITICAL: document.write with user data  
document.write('<p>Hello: ' + userInput + '</p>');

// ❌ CRITICAL: eval with user input
const userScript = new URLSearchParams(window.location.search).get('script');
if (userScript) {
    eval(userScript);
}
</script>
</body>
</html>`,
    'secure-example.js': `// ✅ SECURE: Safe DOM manipulation
function displayContent(userInput) {
    const output = document.getElementById('output');
    output.textContent = userInput; // Safe: uses textContent
}

// ✅ SECURE: Input sanitization
function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

// ✅ SECURE: Safe element creation
function createSafeElement(content) {
    const p = document.createElement('p');
    p.textContent = content;
    return p;
}`
  };

  const runSecurityScan = async (filename: string, content: string) => {
    setIsScanning(true);
    setSelectedFile(filename);
    
    // Simulate scanning delay
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split('\n');
    
    // XSS Detection patterns
    const patterns = [
      {
        regex: /\.innerHTML\s*=/gi,
        type: 'XSS_INNERHTML',
        severity: 'HIGH' as const,
        description: 'Direct innerHTML assignment can lead to XSS vulnerabilities',
        suggestion: 'Use textContent or sanitize HTML with DOMPurify'
      },
      {
        regex: /document\.write\s*\(/gi,
        type: 'XSS_DOCUMENT_WRITE', 
        severity: 'CRITICAL' as const,
        description: 'document.write() can execute malicious scripts',
        suggestion: 'Use modern DOM manipulation methods like createElement'
      },
      {
        regex: /eval\s*\(/gi,
        type: 'CODE_INJECTION',
        severity: 'CRITICAL' as const,
        description: 'eval() can execute arbitrary code and is highly dangerous',
        suggestion: 'Use JSON.parse() for data or refactor to avoid eval'
      },
      {
        regex: /\.outerHTML\s*=/gi,
        type: 'XSS_OUTERHTML',
        severity: 'HIGH' as const,
        description: 'Direct outerHTML assignment can lead to XSS vulnerabilities', 
        suggestion: 'Use safe DOM manipulation methods or sanitize content'
      }
    ];
    
    lines.forEach((line, index) => {
      patterns.forEach(pattern => {
        if (pattern.regex.test(line)) {
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

    const scanResult: ScanResult = {
      filename,
      scanTime: new Date().toISOString(),
      vulnerabilityCount: vulnerabilities.length,
      vulnerabilities,
      riskLevel: vulnerabilities.some(v => v.severity === 'CRITICAL') ? 'CRITICAL' :
                 vulnerabilities.some(v => v.severity === 'HIGH') ? 'HIGH' :
                 vulnerabilities.length > 0 ? 'MEDIUM' : 'LOW'
    };

    // Generate security alert
    let alert: SecurityAlert;
    if (vulnerabilities.length === 0) {
      alert = {
        type: 'SUCCESS',
        title: '✅ Security Scan Passed',
        message: 'No security vulnerabilities detected',
        severity: 'LOW',
        color: 'success'
      };
    } else {
      const criticalCount = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
      if (criticalCount > 0) {
        alert = {
          type: 'CRITICAL',
          title: '🚨 Critical Security Issues Detected',
          message: `${criticalCount} critical vulnerabilities require immediate attention`,
          severity: 'CRITICAL',
          color: 'destructive',
          details: vulnerabilities.filter(v => v.severity === 'CRITICAL')
        };
      } else {
        alert = {
          type: 'HIGH',
          title: '⚠️ Security Issues Detected', 
          message: `${vulnerabilities.length} vulnerabilities found`,
          severity: 'HIGH',
          color: 'warning',
          details: vulnerabilities
        };
      }
    }

    // Update logs
    const newLogs = [
      `${new Date().toISOString().split('T')[0]} ${new Date().toLocaleTimeString()} [FILE_SAVE] Scanning file: ${filename}`,
      vulnerabilities.length > 0 
        ? `${new Date().toISOString().split('T')[0]} ${new Date().toLocaleTimeString()} [VULNERABILITY_DETECTED] ${vulnerabilities.length} vulnerabilities found`
        : `${new Date().toISOString().split('T')[0]} ${new Date().toLocaleTimeString()} [SCAN_CLEAN] No vulnerabilities detected`
    ];
    
    setScanResults(prev => [scanResult, ...prev.slice(0, 4)]);
    setSecurityAlert(alert);
    setSecurityLog(prev => [...newLogs, ...prev.slice(0, 8)]);
    setIsScanning(false);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-destructive text-destructive-foreground';
      case 'HIGH': return 'bg-warning text-warning-foreground';
      case 'MEDIUM': return 'bg-info text-info-foreground';
      case 'LOW': return 'bg-success text-success-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  useEffect(() => {
    // Initialize with some demo logs
    setSecurityLog([
      `${new Date().toISOString().split('T')[0]} ${new Date().toLocaleTimeString()} [INIT] KiroSpecGuard initialized with security specifications`,
      `${new Date().toISOString().split('T')[0]} ${new Date().toLocaleTimeString()} [HOOK] File save hook registered successfully`,
      `${new Date().toISOString().split('T')[0]} ${new Date().toLocaleTimeString()} [READY] Security monitoring active`
    ]);
  }, []);

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center gap-3">
            <Shield className="h-10 w-10 text-primary" />
            <h1 className="text-4xl font-bold text-foreground">KiroSpecGuard</h1>
          </div>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Security & Compliance Assistant for Kiro IDE - Transform natural language specs into working security logic
          </p>
        </div>

        <Tabs defaultValue="dashboard" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="dashboard" className="flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Dashboard
            </TabsTrigger>
            <TabsTrigger value="specs" className="flex items-center gap-2">
              <FileText className="h-4 w-4" />
              Specifications
            </TabsTrigger>
            <TabsTrigger value="demo" className="flex items-center gap-2">
              <Play className="h-4 w-4" />
              Live Demo
            </TabsTrigger>
            <TabsTrigger value="logs" className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              Security Logs
            </TabsTrigger>
          </TabsList>

          {/* Dashboard Tab */}
          <TabsContent value="dashboard" className="space-y-6">
            {/* Security Alert */}
            {securityAlert && (
              <Alert className={`border-l-4 ${
                securityAlert.color === 'success' ? 'border-l-success bg-success/10' :
                securityAlert.color === 'destructive' ? 'border-l-destructive bg-destructive/10' :
                securityAlert.color === 'warning' ? 'border-l-warning bg-warning/10' :
                'border-l-info bg-info/10'
              }`}>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  <div className="space-y-2">
                    <div className="font-semibold">{securityAlert.title}</div>
                    <div>{securityAlert.message}</div>
                    {securityAlert.details && securityAlert.details.length > 0 && (
                      <div className="mt-3 space-y-2">
                        {securityAlert.details.slice(0, 3).map((vuln, index) => (
                          <div key={index} className="text-sm bg-background/50 p-2 rounded">
                            <div className="font-mono text-xs">Line {vuln.line}: {vuln.code}</div>
                            <div className="text-muted-foreground mt-1">{vuln.suggestion}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </AlertDescription>
              </Alert>
            )}

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Total Scans</p>
                      <p className="text-2xl font-bold">{scanResults.length}</p>
                    </div>
                    <FileText className="h-8 w-8 text-primary" />
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Vulnerabilities</p>
                      <p className="text-2xl font-bold text-warning">
                        {scanResults.reduce((acc, result) => acc + result.vulnerabilityCount, 0)}
                      </p>
                    </div>
                    <AlertTriangle className="h-8 w-8 text-warning" />
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Risk Level</p>
                      <p className="text-2xl font-bold">
                        {scanResults.length > 0 ? scanResults[0].riskLevel : 'NONE'}
                      </p>
                    </div>
                    <Shield className="h-8 w-8 text-primary" />
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Status</p>
                      <p className="text-2xl font-bold text-success">Active</p>
                    </div>
                    <CheckCircle className="h-8 w-8 text-success" />
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Recent Scan Results */}
            {scanResults.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Recent Scan Results</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {scanResults.slice(0, 3).map((result, index) => (
                      <div key={index} className="flex items-center justify-between p-4 bg-muted rounded-lg">
                        <div className="flex items-center gap-3">
                          <Code className="h-5 w-5 text-muted-foreground" />
                          <div>
                            <div className="font-medium">{result.filename}</div>
                            <div className="text-sm text-muted-foreground">
                              Scanned at {formatTimestamp(result.scanTime)}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge className={getSeverityColor(result.riskLevel)}>
                            {result.riskLevel}
                          </Badge>
                          <span className="text-sm text-muted-foreground">
                            {result.vulnerabilityCount} issues
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Specifications Tab */}
          <TabsContent value="specs" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileText className="h-5 w-5" />
                  Security Specifications (.kiro/specs/security_spec.kiro)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {specifications.map((spec, index) => (
                    <div key={index} className="flex items-start gap-3 p-3 bg-muted rounded-lg">
                      <CheckCircle className="h-5 w-5 text-success mt-0.5" />
                      <span>{spec}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>How It Works</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="text-center p-4 bg-muted rounded-lg">
                    <FileText className="h-8 w-8 text-primary mx-auto mb-2" />
                    <h3 className="font-semibold mb-2">1. Write Specs</h3>
                    <p className="text-sm text-muted-foreground">
                      Define security requirements in natural language
                    </p>
                  </div>
                  <div className="text-center p-4 bg-muted rounded-lg">
                    <Shield className="h-8 w-8 text-primary mx-auto mb-2" />
                    <h3 className="font-semibold mb-2">2. Auto Scan</h3>
                    <p className="text-sm text-muted-foreground">
                      KiroSpecGuard automatically scans on file save
                    </p>
                  </div>
                  <div className="text-center p-4 bg-muted rounded-lg">
                    <CheckCircle className="h-8 w-8 text-primary mx-auto mb-2" />
                    <h3 className="font-semibold mb-2">3. Get Alerts</h3>
                    <p className="text-sm text-muted-foreground">
                      Receive immediate security alerts with fixes
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Demo Tab */}
          <TabsContent value="demo" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Live Security Scanning Demo</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-muted-foreground">
                  Select a demo file to see KiroSpecGuard in action. The vulnerable file contains XSS and injection vulnerabilities.
                </p>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {Object.entries(demoFiles).map(([filename, content]) => (
                    <Card key={filename} className="cursor-pointer hover:bg-accent transition-colors">
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-2">
                            <Code className="h-4 w-4" />
                            <span className="font-medium">{filename}</span>
                          </div>
                          <Badge variant={filename.includes('vulnerable') ? 'destructive' : 'secondary'}>
                            {filename.includes('vulnerable') ? 'Vulnerable' : 'Secure'}
                          </Badge>
                        </div>
                        <Button 
                          onClick={() => runSecurityScan(filename, content)}
                          disabled={isScanning}
                          className="w-full"
                        >
                          {isScanning && selectedFile === filename ? (
                            <>Scanning...</>
                          ) : (
                            <>
                              <Play className="h-4 w-4 mr-2" />
                              Scan File
                            </>
                          )}
                        </Button>
                      </CardContent>
                    </Card>
                  ))}
                </div>

                {/* Vulnerability Details */}
                {scanResults.length > 0 && scanResults[0].vulnerabilities.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle>Detected Vulnerabilities</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {scanResults[0].vulnerabilities.map((vuln, index) => (
                          <div key={index} className="p-4 bg-muted rounded-lg border-l-4 border-l-destructive">
                            <div className="flex items-center justify-between mb-2">
                              <Badge className={getSeverityColor(vuln.severity)}>
                                {vuln.severity}
                              </Badge>
                              <span className="text-sm text-muted-foreground">
                                Line {vuln.line}
                              </span>
                            </div>
                            <div className="font-mono text-sm bg-background p-2 rounded mb-2">
                              {vuln.code}
                            </div>
                            <div className="text-sm mb-2">{vuln.description}</div>
                            <div className="text-sm text-success">
                              <strong>Fix:</strong> {vuln.suggestion}
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Logs Tab */}
          <TabsContent value="logs" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="h-5 w-5" />
                  Security Decision Log (.kiro/steering/security_decisions.log)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="bg-terminal text-terminal-foreground p-4 rounded-lg font-mono text-sm space-y-1 max-h-96 overflow-y-auto">
                  {securityLog.map((log, index) => (
                    <div key={index} className="whitespace-nowrap">
                      {log}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Integration Status</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <CheckCircle className="h-5 w-5 text-success" />
                      <span>Kiro IDE Integration Active</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle className="h-5 w-5 text-success" />
                      <span>File Save Hooks Registered</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle className="h-5 w-5 text-success" />
                      <span>Real-time Scanning Enabled</span>
                    </div>
                  </div>
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <CheckCircle className="h-5 w-5 text-success" />
                      <span>Compliance Docs Generator Ready</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle className="h-5 w-5 text-success" />
                      <span>Security Specifications Loaded</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle className="h-5 w-5 text-success" />
                      <span>Audit Trail Active</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default SecurityDashboard;