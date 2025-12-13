import re
from dataclasses import dataclass
from typing import List, Dict, Set
from enum import Enum


class SecretSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SecretFinding:
    secret_type: str
    matched_value: str
    severity: str
    source_url: str
    context: str
    recommendation: str


class SecretsScanner:
    SECRET_PATTERNS = [
        {
            'name': 'AWS Access Key',
            'pattern': r'AKIA[0-9A-Z]{16}',
            'severity': SecretSeverity.CRITICAL,
            'recommendation': 'Rotate the AWS access key immediately and remove from code'
        },
        {
            'name': 'AWS Secret Key',
            'pattern': r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]',
            'severity': SecretSeverity.CRITICAL,
            'recommendation': 'Rotate the AWS secret key immediately'
        },
        {
            'name': 'GitHub Token',
            'pattern': r'ghp_[0-9a-zA-Z]{36}',
            'severity': SecretSeverity.CRITICAL,
            'recommendation': 'Revoke the GitHub token immediately'
        },
        {
            'name': 'GitHub OAuth',
            'pattern': r'gho_[0-9a-zA-Z]{36}',
            'severity': SecretSeverity.CRITICAL,
            'recommendation': 'Revoke the GitHub OAuth token immediately'
        },
        {
            'name': 'GitHub App Token',
            'pattern': r'(?:ghu|ghs)_[0-9a-zA-Z]{36}',
            'severity': SecretSeverity.CRITICAL,
            'recommendation': 'Revoke the GitHub App token immediately'
        },
        {
            'name': 'Slack Token',
            'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Revoke the Slack token and generate a new one'
        },
        {
            'name': 'Slack Webhook',
            'pattern': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Regenerate the Slack webhook URL'
        },
        {
            'name': 'Discord Webhook',
            'pattern': r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Regenerate the Discord webhook URL'
        },
        {
            'name': 'Stripe API Key',
            'pattern': r'sk_live_[0-9a-zA-Z]{24,}',
            'severity': SecretSeverity.CRITICAL,
            'recommendation': 'Rotate the Stripe live API key immediately'
        },
        {
            'name': 'Stripe Test Key',
            'pattern': r'sk_test_[0-9a-zA-Z]{24,}',
            'severity': SecretSeverity.MEDIUM,
            'recommendation': 'Remove test keys from production code'
        },
        {
            'name': 'Stripe Publishable Key',
            'pattern': r'pk_(?:live|test)_[0-9a-zA-Z]{24,}',
            'severity': SecretSeverity.LOW,
            'recommendation': 'Publishable keys are meant to be public, but verify exposure is intentional'
        },
        {
            'name': 'Google API Key',
            'pattern': r'AIza[0-9A-Za-z\-_]{35}',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Restrict or regenerate the Google API key'
        },
        {
            'name': 'Google OAuth',
            'pattern': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'severity': SecretSeverity.MEDIUM,
            'recommendation': 'Review OAuth client exposure'
        },
        {
            'name': 'Firebase API Key',
            'pattern': r'(?i)firebase.*?[\'"][A-Za-z0-9_-]{20,}[\'"]',
            'severity': SecretSeverity.MEDIUM,
            'recommendation': 'Review Firebase security rules'
        },
        {
            'name': 'Twilio API Key',
            'pattern': r'SK[0-9a-fA-F]{32}',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Rotate the Twilio API key'
        },
        {
            'name': 'Twilio Account SID',
            'pattern': r'AC[a-zA-Z0-9_\-]{32}',
            'severity': SecretSeverity.MEDIUM,
            'recommendation': 'Account SID exposure may enable unauthorized access'
        },
        {
            'name': 'Mailgun API Key',
            'pattern': r'key-[0-9a-zA-Z]{32}',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Rotate the Mailgun API key'
        },
        {
            'name': 'SendGrid API Key',
            'pattern': r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9_-]{43}',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Rotate the SendGrid API key'
        },
        {
            'name': 'Heroku API Key',
            'pattern': r'(?i)heroku.*?[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Regenerate the Heroku API key'
        },
        {
            'name': 'Private Key',
            'pattern': r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            'severity': SecretSeverity.CRITICAL,
            'recommendation': 'Remove private key exposure and rotate all affected systems'
        },
        {
            'name': 'JWT Token',
            'pattern': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            'severity': SecretSeverity.MEDIUM,
            'recommendation': 'Review JWT exposure and ensure proper expiration'
        },
        {
            'name': 'Basic Auth Credentials',
            'pattern': r'(?i)(?:basic\s+)[a-zA-Z0-9+/]{20,}={0,2}',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Remove hardcoded Basic Auth credentials'
        },
        {
            'name': 'Bearer Token',
            'pattern': r'(?i)bearer\s+[a-zA-Z0-9_\-\.]+',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Remove exposed Bearer tokens'
        },
        {
            'name': 'Password in URL',
            'pattern': r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'"][^\'"]{4,}[\'"]',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Remove hardcoded passwords'
        },
        {
            'name': 'Database Connection String',
            'pattern': r'(?:mongodb|mysql|postgres|postgresql|redis|mssql)://[^\s<>"\']+',
            'severity': SecretSeverity.CRITICAL,
            'recommendation': 'Remove database credentials from exposed code'
        },
        {
            'name': 'Generic API Key',
            'pattern': r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*[\'"][a-zA-Z0-9_\-]{16,}[\'"]',
            'severity': SecretSeverity.MEDIUM,
            'recommendation': 'Review and rotate exposed API keys'
        },
        {
            'name': 'Generic Secret',
            'pattern': r'(?i)(?:secret|token|auth)\s*[:=]\s*[\'"][a-zA-Z0-9_\-]{16,}[\'"]',
            'severity': SecretSeverity.MEDIUM,
            'recommendation': 'Review and rotate exposed secrets'
        },
        {
            'name': 'NPM Token',
            'pattern': r'npm_[A-Za-z0-9]{36}',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Revoke the NPM token immediately'
        },
        {
            'name': 'OpenAI API Key',
            'pattern': r'sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Rotate the OpenAI API key'
        },
        {
            'name': 'Anthropic API Key',
            'pattern': r'sk-ant-[a-zA-Z0-9\-_]{80,}',
            'severity': SecretSeverity.HIGH,
            'recommendation': 'Rotate the Anthropic API key'
        },
    ]

    def __init__(self):
        self.findings: List[SecretFinding] = []
        self.seen_secrets: Set[str] = set()
        self.stats: Dict[str, int] = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

    def scan_content(self, content: str, source_url: str = "") -> List[SecretFinding]:
        found_secrets = []
        
        for secret_def in self.SECRET_PATTERNS:
            try:
                pattern = secret_def['pattern']
                matches = re.finditer(pattern, content, re.MULTILINE)
                
                for match in matches:
                    matched_value = match.group(0)
                    
                    if self._is_false_positive(matched_value, secret_def['name']):
                        continue
                    
                    secret_hash = f"{secret_def['name']}:{matched_value[:20]}"
                    if secret_hash in self.seen_secrets:
                        continue
                    self.seen_secrets.add(secret_hash)
                    
                    start = max(0, match.start() - 30)
                    end = min(len(content), match.end() + 30)
                    context = content[start:end].replace('\n', ' ').strip()
                    
                    masked_value = self._mask_secret(matched_value)
                    
                    severity = secret_def['severity'].value
                    finding = SecretFinding(
                        secret_type=secret_def['name'],
                        matched_value=masked_value,
                        severity=severity,
                        source_url=source_url,
                        context=self._mask_context(context),
                        recommendation=secret_def['recommendation']
                    )
                    
                    found_secrets.append(finding)
                    self.findings.append(finding)
                    self.stats[severity] += 1
                    
            except re.error:
                continue
        
        return found_secrets

    def _is_false_positive(self, value: str, secret_type: str) -> bool:
        placeholder_patterns = [
            r'^x{4,}$',
            r'^\*{4,}$',
            r'^\.{4,}$',
            r'^example',
            r'^test',
            r'^sample',
            r'^placeholder',
            r'^your[_-]',
            r'^insert[_-]',
            r'^REPLACE',
            r'^TODO',
            r'^\$\{',
            r'^{{',
            r'^<',
        ]
        
        for pattern in placeholder_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return True
        
        if len(set(value.replace('-', '').replace('_', ''))) < 3:
            return True
        
        return False

    def _mask_secret(self, value: str) -> str:
        if len(value) <= 8:
            return value[:2] + '*' * (len(value) - 2)
        return value[:4] + '*' * (len(value) - 8) + value[-4:]

    def _mask_context(self, context: str) -> str:
        masked = context
        for secret_def in self.SECRET_PATTERNS:
            try:
                matches = re.finditer(secret_def['pattern'], masked)
                for match in matches:
                    masked = masked.replace(match.group(0), self._mask_secret(match.group(0)))
            except:
                pass
        return masked

    def get_findings(self) -> List[dict]:
        return [
            {
                'type': f.secret_type,
                'value': f.matched_value,
                'severity': f.severity,
                'source': f.source_url,
                'context': f.context,
                'recommendation': f.recommendation
            }
            for f in self.findings
        ]

    def get_stats(self) -> dict:
        return {
            'total': len(self.findings),
            'by_severity': self.stats.copy(),
            'types_found': list(set(f.secret_type for f in self.findings))
        }

    def clear(self):
        self.findings = []
        self.seen_secrets = set()
        self.stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
