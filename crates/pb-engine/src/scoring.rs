//! Detections → verdict and score.
//!
//! | Source                                   | Verdict                                              |
//! |------------------------------------------|------------------------------------------------------|
//! | hash allowlisted (local or bundle)       | **Clean**, detections dropped (decided before scoring) |
//! | hash DB hit                              | Malicious (confidence 0.99)                          |
//! | ClamAV signature                         | Malicious; `PUA.*` / `Heuristics.*` → Suspicious     |
//! | YARA / heuristic, critical or high       | Malicious, or Suspicious if the signer is trusted    |
//! | YARA / heuristic, medium                 | Suspicious                                           |
//! | YARA / heuristic, low or info            | recorded, verdict stays Clean                        |
//! | ML score ≥ threshold                     | Suspicious, never more                               |
//!
//! The file verdict is the maximum over its detections (and, for containers, over their members);
//! the score is the maximum *adjusted* confidence (trusted-signer downgrades cap it at 0.6, clean-level
//! detections at 0.3). Scan errors never produce a verdict by themselves.

use pb_core::model::{Detection, DetectionEngine, Severity, Verdict};

/// Verdict and adjusted confidence implied by one detection.
pub fn detection_verdict(d: &Detection, trusted_signer: bool) -> (Verdict, f32) {
    let conf = if d.confidence.is_finite() {
        d.confidence.clamp(0.0, 1.0)
    } else {
        0.0
    };
    match d.engine {
        DetectionEngine::HashDb => (Verdict::Malicious, conf),
        DetectionEngine::ClamAv => {
            if d.name.starts_with("PUA.") || d.name.starts_with("Heuristics.") {
                (Verdict::Suspicious, conf.min(0.7))
            } else {
                (Verdict::Malicious, conf)
            }
        }
        DetectionEngine::Yara | DetectionEngine::Heuristic => match d.severity {
            Severity::Critical | Severity::High => {
                if trusted_signer {
                    (Verdict::Suspicious, conf.min(0.6))
                } else {
                    (Verdict::Malicious, conf)
                }
            }
            Severity::Medium => (Verdict::Suspicious, conf.min(0.8)),
            Severity::Low | Severity::Info => (Verdict::Clean, conf.min(0.3)),
        },
        DetectionEngine::Ml | DetectionEngine::VirusTotal => (Verdict::Suspicious, conf),
    }
}

/// Combined verdict and score of a set of detections.
pub fn score(detections: &[Detection], trusted_signer: bool) -> (Verdict, f32) {
    detections
        .iter()
        .map(|d| detection_verdict(d, trusted_signer))
        .fold((Verdict::Clean, 0.0f32), |(v, s), (dv, ds)| {
            (v.max(dv), s.max(ds))
        })
}

/// True when a detection comes from a signature engine strong enough for auto-quarantine
/// (hash DB, ClamAV non-PUA, YARA high/critical) — the daemon's `realtime.auto_quarantine` policy.
pub fn is_signature_grade(d: &Detection, trusted_signer: bool) -> bool {
    matches!(
        d.engine,
        DetectionEngine::HashDb
            | DetectionEngine::ClamAv
            | DetectionEngine::Yara
            | DetectionEngine::Heuristic
    ) && detection_verdict(d, trusted_signer).0 == Verdict::Malicious
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(engine: DetectionEngine, name: &str, severity: Severity, confidence: f32) -> Detection {
        Detection {
            engine,
            name: name.into(),
            severity,
            confidence,
            details: None,
        }
    }

    #[test]
    fn table() {
        use DetectionEngine::*;
        assert_eq!(score(&[], false), (Verdict::Clean, 0.0));
        assert_eq!(
            score(&[det(HashDb, "x", Severity::Critical, 0.99)], true).0,
            Verdict::Malicious
        );
        assert_eq!(
            score(
                &[det(ClamAv, "Osx.Trojan.Amos", Severity::High, 0.95)],
                false
            )
            .0,
            Verdict::Malicious
        );
        assert_eq!(
            score(
                &[det(ClamAv, "PUA.Osx.Adware.Pirrit", Severity::Medium, 0.95)],
                false
            )
            .0,
            Verdict::Suspicious
        );
        assert_eq!(
            score(
                &[det(
                    ClamAv,
                    "Heuristics.Encrypted.Zip",
                    Severity::Medium,
                    0.95
                )],
                false
            )
            .0,
            Verdict::Suspicious
        );
        assert_eq!(
            score(&[det(Yara, "r", Severity::High, 0.9)], false),
            (Verdict::Malicious, 0.9)
        );
        assert_eq!(
            score(&[det(Yara, "r", Severity::Critical, 0.95)], true),
            (Verdict::Suspicious, 0.6)
        );
        assert_eq!(
            score(&[det(Heuristic, "r", Severity::Medium, 0.6)], false).0,
            Verdict::Suspicious
        );
        assert_eq!(
            score(&[det(Yara, "r", Severity::Low, 0.9)], false),
            (Verdict::Clean, 0.3)
        );
        assert_eq!(
            score(&[det(Ml, "ml", Severity::Medium, 0.99)], false),
            (Verdict::Suspicious, 0.99)
        );
        let mixed = [
            det(Ml, "ml", Severity::Medium, 0.97),
            det(HashDb, "h", Severity::Critical, 0.99),
        ];
        assert_eq!(score(&mixed, false), (Verdict::Malicious, 0.99));
        assert!(!is_signature_grade(
            &det(Ml, "ml", Severity::Critical, 1.0),
            false
        ));
        assert!(is_signature_grade(
            &det(Yara, "r", Severity::High, 0.9),
            false
        ));
        assert!(!is_signature_grade(
            &det(Yara, "r", Severity::High, 0.9),
            true
        ));
    }
}
