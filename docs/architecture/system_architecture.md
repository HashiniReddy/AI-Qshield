# AI-QShield System Architecture

## 1. Input Layer

The system accepts:

- QR image
- Camera input

## 2. QR Intelligence Layer

Responsible for:

- QR detection
- QR decoding
- Content extraction
- Input validation

## 3. URL Intelligence Layer

Analyzes:

- URL structure
- URL length
- HTTPS
- IP-based URLs
- Subdomains
- Keywords
- Obfuscation
- Entropy

## 4. Domain Intelligence Layer

Analyzes domain-related security signals.

## 5. Redirect Intelligence Layer

Analyzes:

- Redirect count
- Redirect chain
- Destination changes
- Final destination

## 6. Behavioral Analysis Layer

Analyzes suspicious characteristics such as:

- Obfuscation
- Encoding
- Entropy
- Suspicious parameters
- Domain behavior
- Redirect behavior
- Impersonation patterns

## 7. Threat Intelligence Layer

Checks known security indicators and reputation information.

## 8. Risk Fusion Layer

Combines security signals and produces a risk score from 0–100.

## 9. Attack Fingerprinting Layer

Identifies characteristics of likely quishing attacks.

## 10. Explainability Layer

Explains why the QR-linked content was classified as risky.

## 11. Response Layer

Provides:

- Warning
- Evidence preservation
- Reporting

## 12. SOC Dashboard

Displays:

- Risk score
- Attack type
- Scan history
- Trends
- Evidence
- Reports