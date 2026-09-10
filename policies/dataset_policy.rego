package dataset_policy

import rego.v1

default decision := "REJECT"

default reasons := ["Default security policy triggered: rejection required."]

# Rule 1: Immediate REJECT if cryptographic verification failed
decision := "REJECT" if {
    not input.cryptographic_verified
}

reasons := ["Cryptographic integrity check failed. Stored SHA-256 or ML-DSA-65 signature is invalid."] if {
    not input.cryptographic_verified
}

# Rule 2: QUARANTINE if critical or high risk score, or high severity findings present
decision := "QUARANTINE" if {
    input.cryptographic_verified
    input.risk_score >= 50
}

decision := "QUARANTINE" if {
    input.cryptographic_verified
    input.high_severity_findings > 0
}

decision := "QUARANTINE" if {
    input.cryptographic_verified
    input.human_review_required == true
}

reasons := [sprintf("High risk score (%v/100) requires isolation in quarantine for human remediation.", [input.risk_score])] if {
    input.cryptographic_verified
    input.risk_score >= 50
}

reasons := [sprintf("Detected %v high-severity adversarial findings requiring human-in-the-loop review.", [input.high_severity_findings])] if {
    input.cryptographic_verified
    input.high_severity_findings > 0
    input.risk_score < 50
}

# Rule 3: APPROVE if cryptographically verified and no high severity findings and risk is acceptable
decision := "APPROVE" if {
    input.cryptographic_verified
    input.risk_score < 50
    input.high_severity_findings == 0
    not input.human_review_required
}

reasons := ["Dataset passed post-quantum cryptographic verification and meets enterprise safety risk thresholds."] if {
    input.cryptographic_verified
    input.risk_score < 50
    input.high_severity_findings == 0
    not input.human_review_required
}
