package dataset_policy

import rego.v1

default decision := "REJECT"

default reasons := ["Default security policy triggered: rejection required."]

# Rule 1: Immediate REJECT if cryptographic verification failed or risk score >= 65
decision := "REJECT" if {
    not input.cryptographic_verified
}

decision := "REJECT" if {
    input.risk_score >= 65
}

reasons := ["Cryptographic integrity check failed. Stored SHA-256 or ML-DSA-65 signature is invalid."] if {
    not input.cryptographic_verified
}

reasons := [sprintf("High risk score (%v/100) exceeds safety threshold. Dataset rejected from model training.", [input.risk_score])] if {
    input.cryptographic_verified
    input.risk_score >= 65
}

# Rule 2: QUARANTINE if moderate risk score (20 to 64) or human review required
decision := "QUARANTINE" if {
    input.cryptographic_verified
    input.risk_score >= 20
    input.risk_score < 65
}

decision := "QUARANTINE" if {
    input.cryptographic_verified
    input.human_review_required == true
    input.risk_score < 65
}

reasons := [sprintf("Moderate risk score (%v/100) requires isolation in quarantine for human remediation.", [input.risk_score])] if {
    input.cryptographic_verified
    input.risk_score >= 20
    input.risk_score < 65
}

# Rule 3: APPROVE if cryptographically verified and risk score < 20 and no pending review
decision := "APPROVE" if {
    input.cryptographic_verified
    input.risk_score < 20
    not input.human_review_required
}

reasons := ["Dataset passed post-quantum cryptographic verification and meets enterprise safety risk thresholds."] if {
    input.cryptographic_verified
    input.risk_score < 20
    not input.human_review_required
}
