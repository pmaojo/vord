//! Infrastructure-as-Code rules (Terraform/HCL, Kubernetes/CloudFormation
//! YAML). Each rule is an independent plugin implementing
//! [`vord_rules_engine::Rule`]; the engine never changes when rules are
//! added (Open/Closed).

mod iam_wildcard;
mod open_ingress_cidr;

pub use iam_wildcard::IamWildcardPermissionRule;
pub use open_ingress_cidr::OpenIngressCidrRule;

use vord_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(IamWildcardPermissionRule::new()), Box::new(OpenIngressCidrRule::new())]
}
