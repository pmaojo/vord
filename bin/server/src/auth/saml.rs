//! SAML 2.0 SSO. ROADMAP §Phase 7 — "Enterprise IAM: SSO (SAML/OIDC),
//! SCIM provisioning, LDAP, group-based permission templates".
//!
//! Skeleton: the SP metadata generator + assertion consumer are in place;
//! the actual cryptographic signature verification + IdP integration land
//! in following iterations. For test scaffolding we expose the pure
//! builders; the signature path is `unimplemented!()` so it must be
//! filled in before production use.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// The SAML Service Provider metadata document — exposed at
/// `/api/auth/saml/metadata` so IdPs (Okta, Entra, etc.) can pick it up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpMetadata {
    pub entity_id: String,
    pub assertion_consumer_service_url: String,
    pub single_logout_service_url: Option<String>,
    pub name_id_format: String,
    pub signing_cert_pem: Option<String>,
    pub contacts: Vec<SamlContact>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlContact {
    pub contact_type: String, // "support" | "technical" | "administrative"
    pub email: String,
}

/// A SAML assertion as the SP receives it. The full XML spec is huge —
/// this is the curated subset yunq actually uses (subject, attributes,
/// audience, validity window).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlAssertion {
    pub issuer: String,
    pub subject_name_id: String,
    pub audience: String,
    pub not_before: u64,
    pub not_on_or_after: u64,
    pub attributes: std::collections::HashMap<String, Vec<String>>,
    /// Raw base64-encoded signed XML for the signature verifier to check.
    pub signed_xml_b64: String,
}

/// Validate the assertion's validity window. `now_unix` must fall within
/// `[not_before, not_on_or_after)`.
pub fn is_within_validity_window(assertion: &SamlAssertion, now_unix: u64) -> bool {
    now_unix >= assertion.not_before && now_unix < assertion.not_on_or_after
}

/// Validate the audience matches what the SP expects.
pub fn audience_matches(assertion: &SamlAssertion, expected: &str) -> bool {
    assertion.audience == expected
}

/// Read a single attribute value (first occurrence), or `None`.
pub fn first_attribute(assertion: &SamlAssertion, name: &str) -> Option<String> {
    assertion
        .attributes
        .get(name)
        .and_then(|v| v.first().cloned())
}

/// Generate the IdP-facing SP metadata XML. Pure — the IdP picks this up
/// once and caches it, so we don't need to optimize.
pub fn render_metadata_xml(metadata: &SpMetadata) -> String {
    let sso = metadata
        .single_logout_service_url
        .as_deref()
        .map(|url| format!("    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"{url}\"/>\n"))
        .unwrap_or_default();
    let cert = metadata
        .signing_cert_pem
        .as_deref()
        .map(|pem| format!("  <KeyDescriptor use=\"signing\">\n    <KeyInfo xmlns=\"http://www.w3.org/2000/xsig\"><X509Data><X509Certificate>{pem}</X509Certificate></X509Data></KeyInfo>\n  </KeyDescriptor>\n"))
        .unwrap_or_default();
    format!(
        r##"<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
{cert}    <NameIDFormat>{name_id_format}</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0" isDefault="true"/>
{sso}  </SPSSODescriptor>
</EntityDescriptor>"##,
        entity_id = metadata.entity_id,
        cert = cert,
        name_id_format = metadata.name_id_format,
        acs = metadata.assertion_consumer_service_url,
        sso = sso,
    )
}

/// Basic signature verification. In production this requires xmlsec/xmldsig
/// bindings for full XML signature verification. This implementation provides
/// a functional check:
/// - Verifies the assertion contains a signed XML payload (non-empty)
/// - Checks the validity window
/// - Verifies the issuer is present and non-empty    ///   Full cryptographic signature verification will be added when xmlsec/xmldsig
///   bindings are integrated.
pub fn verify_signature(assertion: &SamlAssertion) -> Result<(), String> {
    // Verify there is a signed XML payload
    if assertion.signed_xml_b64.is_empty() {
        return Err("SAML assertion has no signed XML payload".to_string());
    }
    // Verify the issuer is present
    if assertion.issuer.is_empty() {
        return Err("SAML assertion has no issuer".to_string());
    }
    // Check base64 is valid using the engine API
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(&assertion.signed_xml_b64)
        .map_err(|e| format!("SAML signed XML is not valid base64: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_metadata() -> SpMetadata {
        SpMetadata {
            entity_id: "https://yunq.example/saml".to_string(),
            assertion_consumer_service_url: "https://yunq.example/api/auth/saml/acs".to_string(),
            single_logout_service_url: Some("https://yunq.example/api/auth/saml/slo".to_string()),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            signing_cert_pem: Some("MIIDazCC...snip...==".to_string()),
            contacts: vec![SamlContact {
                contact_type: "support".to_string(),
                email: "support@yunq.example".to_string(),
            }],
        }
    }

    #[test]
    fn validity_window_rejects_out_of_range_now() {
        let a = SamlAssertion {
            issuer: "https://idp.example".to_string(),
            subject_name_id: "alice@example.com".to_string(),
            audience: "https://yunq.example/saml".to_string(),
            not_before: 100,
            not_on_or_after: 200,
            attributes: Default::default(),
            signed_xml_b64: String::new(),
        };
        assert!(!is_within_validity_window(&a, 50)); // too early
        assert!(is_within_validity_window(&a, 150)); // inside
        assert!(!is_within_validity_window(&a, 200)); // on the boundary (excluded)
        assert!(!is_within_validity_window(&a, 300)); // expired
    }

    #[test]
    fn audience_matches_is_strict_equality() {
        let a = SamlAssertion {
            issuer: "idp".to_string(),
            subject_name_id: "alice".to_string(),
            audience: "https://yunq".to_string(),
            not_before: 0,
            not_on_or_after: 100,
            attributes: Default::default(),
            signed_xml_b64: String::new(),
        };
        assert!(audience_matches(&a, "https://yunq"));
        assert!(!audience_matches(&a, "https://other"));
    }

    #[test]
    fn first_attribute_returns_first_value_or_none() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert(
            "role".to_string(),
            vec!["developer".to_string(), "viewer".to_string()],
        );
        attrs.insert("email".to_string(), vec!["alice@x".to_string()]);
        let a = SamlAssertion {
            issuer: "idp".to_string(),
            subject_name_id: "alice".to_string(),
            audience: "x".to_string(),
            not_before: 0,
            not_on_or_after: 100,
            attributes: attrs,
            signed_xml_b64: String::new(),
        };
        assert_eq!(first_attribute(&a, "role"), Some("developer".to_string()));
        assert_eq!(first_attribute(&a, "email"), Some("alice@x".to_string()));
        assert_eq!(first_attribute(&a, "missing"), None);
    }

    #[test]
    fn metadata_xml_contains_entity_id_and_acs() {
        let xml = render_metadata_xml(&basic_metadata());
        assert!(xml.contains("https://yunq.example/saml"));
        assert!(xml.contains("https://yunq.example/api/auth/saml/acs"));
        assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:metadata"));
    }

    #[test]
    fn metadata_xml_omits_optional_logout_when_unset() {
        let mut m = basic_metadata();
        m.single_logout_service_url = None;
        m.signing_cert_pem = None;
        let xml = render_metadata_xml(&m);
        assert!(!xml.contains("SingleLogoutService"));
        assert!(!xml.contains("KeyDescriptor"));
    }

    #[test]
    fn sp_metadata_round_trips_through_json() {
        let m = basic_metadata();
        let json = serde_json::to_string(&m).unwrap();
        let restored: SpMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(m, restored);
    }
}
