use ahash::RandomState;
use log::trace;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while_m_n},
    character::complete::{alphanumeric1, multispace1},
    combinator::{recognize, verify},
    multi::{many0_count, many1_count},
    sequence::{pair, tuple},
    IResult,
};
use std::collections::HashSet;
use url::Host;

fn is_digit(c: char) -> bool {
    c.is_ascii_digit()
}

fn parse_ipv4_octet(input: &str) -> IResult<&str, &str> {
    verify(take_while_m_n(1, 3, is_digit), |val: &str| {
        val.parse::<u8>().is_ok()
    })(input)
}

fn parse_hostname_element(input: &str) -> IResult<&str, &str> {
    verify(
        recognize(many1_count(alt((alphanumeric1, tag("-"), tag("_"))))),
        |val: &str| val.len() <= 63,
    )(input)
}

fn parse_hostname(input: &str) -> IResult<&str, &str> {
    recognize(tuple((
        recognize(many1_count(pair(parse_hostname_element, tag(".")))),
        parse_hostname_element,
    )))(input)
}

fn parse_ipv4_address(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        verify(
            many0_count(pair(parse_ipv4_octet, tag("."))),
            |val: &usize| *val <= 3,
        ),
        parse_ipv4_octet,
    ))(input)
}

fn parse_domainlist_line(input: &str) -> Option<&str> {
    // expect "example.com"
    let Ok((_rest, hostname)) = parse_hostname(input) else {
        return None;
    };
    Some(hostname)
}

fn parse_hostfile_line(input: &str) -> Option<&str> {
    // expect "127.0.0.1 example.com"
    let Ok((_rest, (_ipv4_address, _, hostname))) =
        tuple((parse_ipv4_address, multispace1, parse_hostname))(input)
    else {
        return None;
    };
    Some(hostname)
}

pub fn domainlist(file_body: &str, set: &mut HashSet<Host, RandomState>) {
    for line in file_body.lines() {
        if let Some(value) = parse_domainlist_line(line) {
            if let Ok(host_value) = Host::parse(value) {
                set.insert(host_value);
            } else {
                trace!("Unable to parse hostname in line `{value}`");
            }
        } else if !line.is_empty() && line.trim_start()[0..1] != *"#" {
            trace!("Unable to parse `{line}`");
        }
    }
}

pub fn hostfile(file_body: &str, set: &mut HashSet<Host, RandomState>) {
    for line in file_body.lines() {
        if let Some(value) = parse_hostfile_line(line) {
            if let Ok(host_value) = Host::parse(value) {
                set.insert(host_value);
            } else {
                trace!("Unable to parse hostname in line `{value}`");
            }
        } else if !line.is_empty() && line.trim_start()[0..1] != *"#" {
            trace!("Unable to parse `{line}`");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use ahash::RandomState;
    use fake::{faker, Fake};
    use proptest::{prop_assert_eq, proptest, strategy::Strategy};
    use url::Host;

    use super::{parse_hostfile_line, parse_hostname, parse_ipv4_address, parse_ipv4_octet};
    use crate::parse::{domainlist, hostfile, parse_domainlist_line};

    #[test]
    fn parse_ip4_octet_parses_valid_ipv4_octet() {
        // arrange
        let input_0: &str = "1";
        let input_1: &str = "12";
        let input_2: &str = "123";
        let input_3: &str = "1234";

        // act
        let result_0 = parse_ipv4_octet(input_0);
        let result_1 = parse_ipv4_octet(input_1);
        let result_2 = parse_ipv4_octet(input_2);
        let result_3 = parse_ipv4_octet(input_3);

        // assert
        assert_eq!(result_0, Ok(("", "1")));
        assert_eq!(result_1, Ok(("", "12")));
        assert_eq!(result_2, Ok(("", "123")));
        assert_eq!(result_3, Ok(("4", "123")));
    }

    proptest! {
    #[test]
    fn parse_ip4_octet_parses_valid_ipv4_octet_proptest(octet in 0u8..) {
        // arrange
        let octet_string = octet.to_string();

        // act
        let result = parse_ipv4_octet(&octet_string);

        // assert
        prop_assert_eq!(result, Ok(("", octet_string.as_str())));
    }
    }

    #[test]
    fn parse_ipv4_octet_fails_to_parse_invalid_ipv4_octet() {
        // arrange
        let input_0: &str = "";
        let input_1: &str = ".";
        let input_2: &str = "256";

        // act
        let result_0 = parse_ipv4_octet(input_0);
        let result_1 = parse_ipv4_octet(input_1);
        let result_2 = parse_ipv4_octet(input_2);

        // assert
        assert_eq!(
            result_0,
            Err(nom::Err::Error(nom::error::Error {
                input: "",
                code: nom::error::ErrorKind::TakeWhileMN
            }))
        );
        assert_eq!(
            result_1,
            Err(nom::Err::Error(nom::error::Error {
                input: ".",
                code: nom::error::ErrorKind::TakeWhileMN
            }))
        );
        assert_eq!(
            result_2,
            Err(nom::Err::Error(nom::error::Error {
                input: "256",
                code: nom::error::ErrorKind::Verify
            }))
        );
    }

    fn arb_ipv4_address() -> impl Strategy<Value = String> {
        (0u8.., 0u8.., 0u8.., 0u8..).prop_map(|(octet_0, octet_1, octet_2, octet_3)| {
            format!("{octet_0}.{octet_1}.{octet_2}.{octet_3}")
        })
    }

    proptest! {
    #[test]
    fn parse_ipv4_address_parses_valid_ipv4_proptest(
        ipv4_address in arb_ipv4_address()){
        // arrange

        // act
        let result = parse_ipv4_address(&ipv4_address);

        // assert
        prop_assert_eq!(result, Ok(("", ipv4_address.as_str())));
    }
    }

    #[test]
    fn parse_ipv4_address_parses_valid_ipv4_address() {
        // arrange
        let input_0: &str = "127.0.0.1"; // DevSkim: ignore DS162092 - use of local host IP is in test
        let input_1: &str = "127";
        let input_2: &str = "127.0.0.1 example.com"; // DevSkim: ignore DS162092 - use of local host IP is in test

        // act
        let result_0 = parse_ipv4_address(input_0);
        let result_1 = parse_ipv4_address(input_1);
        let result_2 = parse_ipv4_address(input_2);

        // assert
        assert_eq!(result_0, Ok(("", "127.0.0.1"))); // DevSkim: ignore DS162092 - use of local host IP is in test
        assert_eq!(result_1, Ok(("", "127")));
        assert_eq!(result_2, Ok((" example.com", "127.0.0.1"))); // DevSkim: ignore DS162092 - use of local host IP is in test
    }

    #[test]
    fn parse_ipv4_address_fails_to_parse_invalid_ipv4_address() {
        // arrange
        let input_0: &str = "127.0.0.1.1"; // DevSkim: ignore DS162092 - use of local host IP is in test

        // act
        let result_0 = parse_ipv4_address(input_0);

        // assert
        assert_eq!(
            result_0,
            Err(nom::Err::Error(nom::error::Error {
                input: "127.0.0.1.1", // DevSkim: ignore DS162092 - use of local host IP is in test
                code: nom::error::ErrorKind::Verify
            }))
        );
    }

    #[test]
    fn parse_hostname_parses_valid_hostnames() {
        // arrange
        let input_0: &str = "example.com";
        let input_1: &str = "sub.example.com";
        let input_2: &str = "sub-domain.example.com";
        let input_3: &str = "sub_domain.example.com";

        // act
        let result_0 = parse_hostname(input_0);
        let result_1 = parse_hostname(input_1);
        let result_2 = parse_hostname(input_2);
        let result_3 = parse_hostname(input_3);

        // assert
        assert_eq!(result_0, Ok(("", "example.com")));
        assert_eq!(result_1, Ok(("", "sub.example.com")));
        assert_eq!(result_2, Ok(("", "sub-domain.example.com")));
        assert_eq!(result_3, Ok(("", "sub_domain.example.com")));
    }

    fn arb_subdomain_name() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_-]{1,63}"
    }

    fn arb_top_level_domain() -> impl Strategy<Value = String> {
        (0u8..1).prop_map(|_| faker::internet::en::DomainSuffix().fake::<String>())
    }

    /// There is no limit on number of subdomains in the standards, though each subdomain should be no longer than
    /// 63 octets and the entire domain name should be no longer than 255 octets.  This test does
    /// not currently push right up to those limits.
    fn arb_domain_name() -> impl Strategy<Value = String> {
        (
            arb_subdomain_name(),
            arb_subdomain_name(),
            arb_subdomain_name(),
            arb_top_level_domain(),
            1u32..4,
        )
            .prop_map(|(subdomain_0, subdomain_1, subdomain_2, tld, subdomains)| {
                match subdomains {
                    1 => format!("{subdomain_0}.{tld}"),
                    2 => format!("{subdomain_0}.{subdomain_1}.{tld}"),
                    3 => format!("{subdomain_0}.{subdomain_1}.{subdomain_2}.{tld}"),
                    _ => unreachable!("Unexpected subdomain count"),
                }
            })
    }

    proptest! {
         #[test]
         fn parse_hostname_parses_valid_hostnames_proptest(
    hostname in arb_domain_name())
     {
             // arrange
             // act
             let result = parse_hostname(&hostname);

             // assert
             prop_assert_eq!(result, Ok(("", hostname.as_str())));
         }
         }

    #[test]
    fn parse_domainlist_line_successfully_handles_invalid_input() {
        // arrange
        let input_0: &str = "com";
        let input_1: &str = "# some annotation";

        // act
        let result_0 = parse_domainlist_line(input_0);
        let result_1 = parse_domainlist_line(input_1);

        // assert
        assert_eq!(result_0, None);
        assert_eq!(result_1, None);
    }

    #[test]
    fn parse_domainlist_line_successfully_parses_valid_input() {
        // arrange
        let input_0: &str = "example.com";
        let input_1: &str = "example.com # some annotation";

        // act
        let result_0 = parse_domainlist_line(input_0);
        let result_1 = parse_domainlist_line(input_1);

        // assert
        assert_eq!(result_0, Some("example.com"));
        assert_eq!(result_1, Some("example.com"));
    }

    proptest! {
         #[test]
    fn parse_domainlist_line_successfully_parses_valid_input_proptest(
    hostname in arb_domain_name())
     {
             // arrange

             // act
             let result = parse_domainlist_line(&hostname);

             // assert
             prop_assert_eq!(result, Some(hostname.as_str()));
         }
         }

    #[test]
    fn parse_hostfile_line_successfully_parses_valid_input() {
        // arrange
        let input_0: &str = "127.0.0.1 example.com"; // DevSkim: ignore DS162092 - use of local host IP is in test

        // act
        let result_0 = parse_hostfile_line(input_0);

        // assert
        assert_eq!(result_0, Some("example.com"));
    }

    proptest! {
         #[test]
    fn parse_hostfile_line_successfully_parses_valid_input_proptest(
        ipv4_address in arb_ipv4_address(),
    hostname in arb_domain_name())
     {
             // arrange
             let line = format!("{ipv4_address} {hostname}");

             // act
             let result = parse_hostfile_line(&line);

             // assert
             prop_assert_eq!(result, Some(hostname.as_str()));
         }
         }

    #[test]
    fn domainlist_successfully_parses_valid_input() {
        // arrange
        let input = r"example.com
another-example.com # some annotation

# more annotation
subdomain-which-is-too-long-012345679012345678901234567890123456.com
final-example.com";
        let hasher = RandomState::new();
        let mut hash_set: HashSet<Host, RandomState> = HashSet::with_hasher(hasher);

        // act
        domainlist(input, &mut hash_set);

        // assert
        assert_eq!(hash_set.len(), 3);
        assert!(hash_set.contains(&Host::parse("example.com").unwrap()));
        assert!(hash_set.contains(&Host::parse("another-example.com").unwrap()));
        assert!(hash_set.contains(&Host::parse("final-example.com").unwrap()));
    }

    #[test]
    fn hostfile_successfully_parses_valid_input() {
        // arrange
        let _ = env_logger::builder().is_test(true).try_init();
        let input = "127.0.0.1\texample.com\n0.0.0.0 another-example.com # some annotation\n\n# more annotation\n0.0.0.0\t\tsubdomain-which-is-too-long-012345679012345678901234567890123456.com\n0.0.0.0\tfinal-example.com";
        let hasher = RandomState::new();
        let mut hash_set: HashSet<Host, RandomState> = HashSet::with_hasher(hasher);

        // act
        hostfile(input, &mut hash_set);

        // assert
        assert_eq!(hash_set.len(), 3);
        assert!(hash_set.contains(&Host::parse("example.com").unwrap()));
        assert!(hash_set.contains(&Host::parse("another-example.com").unwrap()));
        assert!(hash_set.contains(&Host::parse("final-example.com").unwrap()));
    }
}
