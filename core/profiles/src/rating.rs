//! A–E ratings derived from issue severity, mirroring SonarQube's rating
//! scale: A = clean, E = at least one blocker.

use std::fmt;

use crate::Severity;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rating {
    A,
    B,
    C,
    D,
    E,
}

impl Rating {
    /// Rating from the worst severity present: no issues (or only info) → A,
    /// minor → B, major → C, critical → D, blocker → E.
    pub fn from_worst_severity(worst: Option<Severity>) -> Self {
        match worst {
            None | Some(Severity::Info) => Rating::A,
            Some(Severity::Minor) => Rating::B,
            Some(Severity::Major) => Rating::C,
            Some(Severity::Critical) => Rating::D,
            Some(Severity::Blocker) => Rating::E,
        }
    }

    pub fn letter(&self) -> char {
        match self {
            Rating::A => 'A',
            Rating::B => 'B',
            Rating::C => 'C',
            Rating::D => 'D',
            Rating::E => 'E',
        }
    }
}

impl fmt::Display for Rating {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.letter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_worst_severity_to_rating() {
        assert_eq!(Rating::from_worst_severity(None), Rating::A);
        assert_eq!(Rating::from_worst_severity(Some(Severity::Info)), Rating::A);
        assert_eq!(Rating::from_worst_severity(Some(Severity::Minor)), Rating::B);
        assert_eq!(Rating::from_worst_severity(Some(Severity::Major)), Rating::C);
        assert_eq!(Rating::from_worst_severity(Some(Severity::Critical)), Rating::D);
        assert_eq!(Rating::from_worst_severity(Some(Severity::Blocker)), Rating::E);
    }

    #[test]
    fn ratings_order_from_best_to_worst() {
        assert!(Rating::A < Rating::E);
    }
}
