Feature: React Auth Token in Web Storage Rule
  As a security auditor
  I want to detect storing sensitive authentication tokens in localStorage or sessionStorage
  So that XSS attacks cannot exfiltrate session tokens from web storage.

  Scenario: Flagging token saved to localStorage
    Given a React TypeScript file containing "localStorage.setItem('access_token', token)"
    When vord scans the file with rule "react:auth-token-in-web-storage"
    Then a Warning finding is reported highlighting Web Storage token risk.

  Scenario: Allowing non-sensitive storage items
    Given a React TypeScript file containing "localStorage.setItem('theme', 'dark')"
    When vord scans the file with rule "react:auth-token-in-web-storage"
    Then no finding is reported.
