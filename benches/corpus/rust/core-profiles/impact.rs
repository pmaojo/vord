//! MQR ("Maintainability, Reliability, Security") issue classification —
//! a second classification axis, layered on top of the classic
//! [`IssueType`] × [`Severity`] model rather than replacing it. An
//! issue is still a Bug/Vulnerability/CodeSmell for backward compatibility,
//! but it also carries one or more [`SoftwareQualityImpact`]s so the same
//! finding can answer both "what kind of issue is this" and "which
//! software qualities does it hurt, and how badly".
//!
//! [`default_impact`] derives the MQR view from the classic one: each
//! classic type maps to exactly one quality (`Bug` -> Reliability,
//! `Vulnerability` -> Security, `CodeSmell` -> Maintainability), and
//! [`ImpactSeverity::from_severity`] carries the severity across. Rules that
//! genuinely affect more than one quality can report additional impacts
//! beyond this default.

use std::fmt;

use crate::{IssueType, Severity};

/// One of the three software qualities an issue is rated against,
/// independently of the classic Bug/Vulnerability/CodeSmell type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SoftwareQuality {
    Maintainability,
    Reliability,
    Security,
}

impl SoftwareQuality {
    pub fn as_str(&self) -> &'static str {
        match self {
            SoftwareQuality::Maintainability => "maintainability",
            SoftwareQuality::Reliability => "reliability",
            SoftwareQuality::Security => "security",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "maintainability" => Some(SoftwareQuality::Maintainability),
            "reliability" => Some(SoftwareQuality::Reliability),
            "security" => Some(SoftwareQuality::Security),
            _ => None,
        }
    }
}

impl fmt::Display for SoftwareQuality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// MQR's own severity scale, ordered from least to most severe. Distinct
/// from the classic per-issue [`Severity`] wheel — this scale exists
/// specifically for impacts — but every classic severity has exactly one
/// MQR equivalent via [`ImpactSeverity::from_severity`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImpactSeverity {
    Info,
    Low,
    Medium,
    High,
    Blocker,
}

impl ImpactSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            ImpactSeverity::Info => "info",
            ImpactSeverity::Low => "low",
            ImpactSeverity::Medium => "medium",
            ImpactSeverity::High => "high",
            ImpactSeverity::Blocker => "blocker",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "info" => Some(ImpactSeverity::Info),
            "low" => Some(ImpactSeverity::Low),
            "medium" => Some(ImpactSeverity::Medium),
            "high" => Some(ImpactSeverity::High),
            "blocker" => Some(ImpactSeverity::Blocker),
            _ => None,
        }
    }

    /// The classic-to-MQR severity mapping: `INFO -> INFO`,
    /// `MINOR -> LOW`, `MAJOR -> MEDIUM`, `CRITICAL -> HIGH`,
    /// `BLOCKER -> BLOCKER`.
    pub fn from_severity(severity: Severity) -> Self {
        match severity {
            Severity::Info => ImpactSeverity::Info,
            Severity::Minor => ImpactSeverity::Low,
            Severity::Major => ImpactSeverity::Medium,
            Severity::Critical => ImpactSeverity::High,
            Severity::Blocker => ImpactSeverity::Blocker,
        }
    }
}

impl fmt::Display for ImpactSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One MQR impact: a software quality and how severely this issue affects
/// it. An issue can carry more than one — e.g. a rule might hurt both
/// Security and Reliability at once — unlike the classic model where an
/// issue has exactly one type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SoftwareQualityImpact {
    pub quality: SoftwareQuality,
    pub severity: ImpactSeverity,
}

/// The MQR impact derived from a classic `(IssueType, Severity)` pair: `Bug` -> Reliability, `Vulnerability`
/// -> Security, `CodeSmell` -> Maintainability, with the severity carried
/// across via [`ImpactSeverity::from_severity`]. This is a *default* — rules
/// that affect more than one quality report additional impacts beyond it.
pub fn default_impact(issue_type: IssueType, severity: Severity) -> SoftwareQualityImpact {
    let quality = match issue_type {
        IssueType::Bug => SoftwareQuality::Reliability,
        IssueType::Vulnerability => SoftwareQuality::Security,
        IssueType::CodeSmell => SoftwareQuality::Maintainability,
    };
    SoftwareQualityImpact { quality, severity: ImpactSeverity::from_severity(severity) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_maps_onto_its_mqr_equivalent() {
        assert_eq!(ImpactSeverity::from_severity(Severity::Info), ImpactSeverity::Info);
        assert_eq!(ImpactSeverity::from_severity(Severity::Minor), ImpactSeverity::Low);
        assert_eq!(ImpactSeverity::from_severity(Severity::Major), ImpactSeverity::Medium);
        assert_eq!(ImpactSeverity::from_severity(Severity::Critical), ImpactSeverity::High);
        assert_eq!(ImpactSeverity::from_severity(Severity::Blocker), ImpactSeverity::Blocker);
    }

    #[test]
    fn impact_severity_ordering() {
        assert!(ImpactSeverity::Blocker > ImpactSeverity::High);
        assert!(ImpactSeverity::Info < ImpactSeverity::Low);
    }

    #[test]
    fn default_impact_maps_each_classic_type_to_its_own_quality() {
        assert_eq!(
            default_impact(IssueType::Bug, Severity::Critical),
            SoftwareQualityImpact { quality: SoftwareQuality::Reliability, severity: ImpactSeverity::High }
        );
        assert_eq!(
            default_impact(IssueType::Vulnerability, Severity::Blocker),
            SoftwareQualityImpact { quality: SoftwareQuality::Security, severity: ImpactSeverity::Blocker }
        );
        assert_eq!(
            default_impact(IssueType::CodeSmell, Severity::Minor),
            SoftwareQualityImpact { quality: SoftwareQuality::Maintainability, severity: ImpactSeverity::Low }
        );
    }

    #[test]
    fn parses_and_displays_round_trip() {
        for quality in [SoftwareQuality::Maintainability, SoftwareQuality::Reliability, SoftwareQuality::Security] {
            assert_eq!(SoftwareQuality::parse(&quality.to_string()), Some(quality));
        }
        for severity in
            [ImpactSeverity::Info, ImpactSeverity::Low, ImpactSeverity::Medium, ImpactSeverity::High, ImpactSeverity::Blocker]
        {
            assert_eq!(ImpactSeverity::parse(&severity.to_string()), Some(severity));
        }
    }
}
