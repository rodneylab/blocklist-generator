use url::Host;

use crate::file_system::Filters;

/// Helper function to find parent domains, up to the second level domain.  For example,
/// with `some.subdomain.example.com` as input, result should be Some, and a vector of
/// `subdomain.example.com`, `example.com`.  `domain` is never included in output.  Returns None
/// for a top-level domain (e.g. `com`) or second-level domain (e.g. `example.com`).
fn parent_domains(domain: &Host) -> Option<Vec<Host>> {
    if let Host::Domain(host_string) = domain {
        let mut result: Vec<Host> = Vec::new();
        let mut sub_domain: String = host_string.to_string();
        while let Some((_, parent_domain)) = sub_domain.split_once('.') {
            if parent_domain.find('.').is_some() {
                result.push(Host::parse(parent_domain).unwrap());
                sub_domain = parent_domain.to_string();
            } else {
                break;
            }
        }

        if !result.is_empty() {
            return Some(result);
        }
    }

    None
}

/// Remove any allowlist members found in `blocklist`.  If the allowlist member is a subdomain, any
/// occurrences of parent domain also get removed (`some.example.com` in allowlist results in
/// `example.com` being removed from `blocklist`)
pub fn filter_blocklist(
    blocklist: &mut std::collections::HashSet<Host, ahash::RandomState>,
    filters: &Filters,
) {
    if let Some(allowed_names_value) = &filters.allowed_names {
        for name in allowed_names_value {
            match Host::parse(name) {
                Ok(value) => {
                    if let Some(parent_domain_values) = parent_domains(&value) {
                        for parent_name in parent_domain_values {
                            if blocklist.remove(&parent_name) {
                                log::info!(
                                "Removed parent domain `{parent_name}` of allowed_names element: \
                                `{name}` from generated blocklist."
                            );
                            }
                        }
                    }
                    if blocklist.remove(&value) {
                        log::info!(
                            "Removed allowed_names element: `{name}` from generated blocklist."
                        );
                    } else {
                        log::info!(
                            "No exact matches for allowed_names element: `{name}` in generated \
                            blocklist."
                        );
                    }
                }
                Err(_) => {
                    log::error!("Ignoring allowed_names element: `{name}`.  Check it is valid.");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use url::Host;

    use crate::{file_system::Filters, filter::filter_blocklist};

    use super::parent_domains;

    #[test]
    fn filter_blocklist_removes_matches() {
        // arrange
        let filters = Filters {
            allowed_names: Some(vec![
                String::from("0.0.0.0"),
                String::from("127.0.0.1"), // DevSkim: ignore DS162092 - use of local host IP is in test
                String::from("255.255.255.255"),
            ]),
            blocked_names: None,
        };

        let hasher = ahash::RandomState::new();
        let mut set: std::collections::HashSet<Host, ahash::RandomState> =
            std::collections::HashSet::with_hasher(hasher);
        set.insert(Host::parse("example.com").unwrap());
        set.insert(Host::parse("another.example.com").unwrap());
        set.insert(Host::parse("127.0.0.1").unwrap()); // DevSkim: ignore DS162092 - use of local host IP is in test
        set.insert(Host::parse("255.255.255.255").unwrap());

        // act
        filter_blocklist(&mut set, &filters);

        // assert
        assert_eq!(set.len(), 2);
        assert!(!set.contains(&Host::parse("127.0.0.1").unwrap(),)); // DevSkim: ignore DS162092 - use of local host IP is in test

        assert!(set.contains(&Host::parse("example.com").unwrap(),));
        assert!(set.contains(&Host::parse("another.example.com").unwrap(),));
    }

    #[test]
    fn filter_blocklist_removes_matches_for_subdomains() {
        // arrange
        let filters = Filters {
            allowed_names: Some(vec![
                String::from("0.0.0.0"),
                String::from("127.0.0.1"), // DevSkim: ignore DS162092 - use of local host IP is in test
                String::from("255.255.255.255"),
                String::from("some.example.com"),
            ]),
            blocked_names: None,
        };

        let hasher = ahash::RandomState::new();
        let mut set: std::collections::HashSet<Host, ahash::RandomState> =
            std::collections::HashSet::with_hasher(hasher);
        set.insert(Host::parse("example.com").unwrap());
        set.insert(Host::parse("another.example.com").unwrap());
        set.insert(Host::parse("127.0.0.1").unwrap()); // DevSkim: ignore DS162092 - use of local host IP is in test

        set.insert(Host::parse("255.255.255.255").unwrap());

        // act
        filter_blocklist(&mut set, &filters);

        // assert
        assert_eq!(set.len(), 1);
        assert!(!set.contains(&Host::parse("127.0.0.1").unwrap(),)); // DevSkim: ignore DS162092 - use of local host IP is in test

        assert!(!set.contains(&Host::parse("example.com").unwrap(),));
        assert!(set.contains(&Host::parse("another.example.com").unwrap(),));
    }

    #[test]
    fn filter_blocklist_keeps_subdomains() {
        // arrange
        let filters = Filters {
            allowed_names: Some(vec![
                String::from("0.0.0.0"),
                String::from("127.0.0.1"), // DevSkim: ignore DS162092 - use of local host IP is in test
                String::from("255.255.255.255"),
                String::from("example.com"),
            ]),
            blocked_names: None,
        };

        let hasher = ahash::RandomState::new();
        let mut set: std::collections::HashSet<Host, ahash::RandomState> =
            std::collections::HashSet::with_hasher(hasher);
        set.insert(Host::parse("example.com").unwrap());
        set.insert(Host::parse("some.example.com").unwrap());
        set.insert(Host::parse("127.0.0.1").unwrap()); // DevSkim: ignore DS162092 - use of local host IP is in test

        set.insert(Host::parse("255.255.255.255").unwrap());

        // act
        filter_blocklist(&mut set, &filters);

        // assert
        assert_eq!(set.len(), 1);
        assert!(!set.contains(&Host::parse("127.0.0.1").unwrap(),)); // DevSkim: ignore DS162092 - use of local host IP is in test

        assert!(!set.contains(&Host::parse("example.com").unwrap(),));
        assert!(set.contains(&Host::parse("some.example.com").unwrap(),));
    }

    #[test]
    fn parent_domains_returns_none_for_tld() {
        // arrange
        let domain = Host::parse("com").unwrap();

        // act
        let outcome = parent_domains(&domain);

        // assert
        assert!(outcome.is_none());
    }

    #[test]
    fn parent_domains_returns_none_for_second_level_domain() {
        // arrange
        let domain = Host::parse("example.com").unwrap();

        // act
        let outcome = parent_domains(&domain);

        // assert
        assert!(outcome.is_none());
    }

    #[test]
    fn parent_domains_returns_parent_domains_as_expected() {
        // arrange
        let domain = Host::parse("another.some.example.com").unwrap();

        // act
        let outcome = parent_domains(&domain);

        // assert
        assert_eq!(
            outcome,
            Some(vec![
                Host::parse("some.example.com").unwrap(),
                Host::parse("example.com").unwrap(),
            ])
        );

        // arrange
        let domain = Host::parse("some.example.com").unwrap();

        // act
        let outcome = parent_domains(&domain);

        // assert
        assert_eq!(outcome, Some(vec![Host::parse("example.com").unwrap(),]));
    }
}
