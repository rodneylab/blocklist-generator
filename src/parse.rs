use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, take_while_m_n},
    character::complete::{alphanumeric1, multispace1},
    combinator::{map, recognize, verify},
    multi::{many_m_n, many0_count, many1_count},
    sequence::{pair, separated_pair},
};
use url::Host;

// octet should not start with a leading zero
fn parse_ipv4_octet(input: &str) -> IResult<&str, &str> {
    let is_digit = |ch: char| ch.is_ascii_digit();

    verify(take_while_m_n(1, 3, is_digit), |val: &str| {
        debug_assert_eq!(val, val.trim());
        match val {
            "0" => true,
            value => {
                if value.starts_with('0') {
                    return false;
                }

                val.parse::<u8>().is_ok()
            }
        }
    })
    .parse(input)
}

fn parse_ipv6_hexadectet(input: &str) -> IResult<&str, &str> {
    let is_hex_digit = |ch: char| ch.is_ascii_hexdigit();

    verify(take_while_m_n(1, 4, is_hex_digit), |val: &str| {
        u16::from_str_radix(val, 16).is_ok()
    })
    .parse(input)
}

fn parse_hostname_element(input: &str) -> IResult<&str, &str> {
    verify(
        recognize(many1_count(alt((alphanumeric1, tag("-"), tag("_"))))),
        |val: &str| val.len() <= 63,
    )
    .parse(input)
}

fn parse_hostname(input: &str) -> IResult<&str, &str> {
    recognize((
        recognize(many1_count(pair(parse_hostname_element, tag(".")))),
        parse_hostname_element,
    ))
    .parse(input)
}

// Accepts one to four octets
fn parse_ipv4_address(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        many_m_n(0, 3, pair(parse_ipv4_octet, tag("."))),
        parse_ipv4_octet,
    ))
    .parse(input)
}

fn parse_ipv6_address(input: &str) -> IResult<&str, &str> {
    // Consecutive sections of zeros are replaced with two colons (::). This may only be used once
    // in an address, as multiple use would render the address indeterminate. A double colon should
    // not be used to denote an omitted single section of zeros.
    // <https://en.wikipedia.org/wiki/IPv6>
    alt((
        // aaaa::bbbb -> aaaa:aaaa:aaaa:aaaa:aaaa::bbbb
        // address that contains a compression group and the
        // compression group is not at the start or end
        recognize((
            parse_ipv6_hexadectet,
            verify(
                map(
                    separated_pair(
                        many0_count(pair(tag(":"), parse_ipv6_hexadectet)),
                        tag("::"),
                        many0_count(pair(parse_ipv6_hexadectet, tag(":"))),
                    ),
                    |(len_0, len_1)| len_0 + len_1,
                ),
                |len| *len < 5,
            ),
            parse_ipv6_hexadectet,
        )),
        // ::aaaa -> ::aaaa:aaaa:aaaa:aaaa:aaaa:aaaa
        // address that starts with a compression group
        recognize((
            tag("::"),
            many_m_n(0, 5, pair(parse_ipv6_hexadectet, tag(":"))),
            parse_ipv6_hexadectet,
        )),
        tag("::"),
        // aaaa:: -> aaaa:aaaa:aaaa:aaaa:aaaa:aaaa::
        // address that ends with a compression group
        recognize((
            parse_ipv6_hexadectet,
            many_m_n(0, 5, pair(tag(":"), parse_ipv6_hexadectet)),
            tag("::"),
        )),
        // full address with no compression
        recognize(pair(
            many_m_n(7, 7, pair(parse_ipv6_hexadectet, tag(":"))),
            parse_ipv6_hexadectet,
        )),
    ))
    .parse(input)
}

// only handles case where the IPv6 prefix uses compression notation
fn parse_ipv4_mapped_ipv6_address(input: &str) -> IResult<&str, &str> {
    recognize(pair(tag("::ffff:"), parse_ipv4_address)).parse(input)
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
    let Ok((_rest, (_ipv4_address, _, hostname))) = (
        alt((
            parse_ipv4_mapped_ipv6_address,
            parse_ipv6_address,
            parse_ipv4_address,
        )),
        multispace1,
        parse_hostname,
    )
        .parse(input)
    else {
        return None;
    };
    Some(hostname)
}

pub fn domainlist(file_body: &str, set: &mut std::collections::HashSet<Host, ahash::RandomState>) {
    for line in file_body.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(value) = parse_domainlist_line(line) {
            if let Ok(host_value) = Host::parse(value) {
                set.insert(host_value);
            } else {
                log::trace!("Unable to parse hostname in domainlist line `{value}`");
            }
        } else {
            log::trace!("Unable to parse domainlist line `{line}`");
        }
    }
}

pub fn hostfile(file_body: &str, set: &mut std::collections::HashSet<Host, ahash::RandomState>) {
    for line in file_body.lines() {
        log::trace!("Parsing hostfile line: `{line}`");
        if let Some(value) = parse_hostfile_line(line) {
            if let Ok(host_value) = Host::parse(value) {
                set.insert(host_value);
            } else {
                log::trace!("Unable to parse hostname in line `{value}`");
            }
        } else if line.trim_start().starts_with('#') {
            log::trace!("Ignoring hostfile comment line: `{line}`");
        } else if !line.trim().is_empty() {
            log::warn!("Unable to parse hostfile line: `{line}`");
        }
    }
}

#[cfg(test)]
mod tests {
    use fake::{Fake, faker};
    use proptest::{prop_assert_eq, proptest, strategy::Strategy};
    use url::Host;

    use super::{
        parse_hostfile_line, parse_hostname, parse_ipv4_address, parse_ipv4_mapped_ipv6_address,
        parse_ipv4_octet, parse_ipv6_address,
    };
    use crate::parse::{domainlist, hostfile, parse_domainlist_line};

    #[test]
    fn parse_ip4_octet_parses_valid_ipv4_octet() {
        // arrange
        let input_0 = "1";
        let input_1 = "12";
        let input_2 = "123";
        let input_3 = "1234";

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

    #[test]
    fn parse_ip4_octet_returns_error_for_invalid_ipv4_octet() {
        // arrange
        let input = "012";

        // act
        let result = parse_ipv4_octet(input);

        // assert
        assert_eq!(
            result,
            Err(nom::Err::Error(nom::error::Error {
                input: "012",
                code: nom::error::ErrorKind::Verify
            }))
        );
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
        let input_0 = "";
        let input_1 = ".";
        let input_2 = "256";

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
        (0u8..1).prop_map(|_| faker::internet::en::IPv4().fake::<String>())
    }

    proptest! {
       #[test]
       fn parse_ipv4_address_parses_valid_address_proptest(
           ipv4_address in arb_ipv4_address()
       ) {
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
        let input_0 = "127.0.0.1"; // DevSkim: ignore DS162092 - use of local host IP is in test
        let input_1 = "127";
        let input_2 = "127.0.0.1 example.com"; // DevSkim: ignore DS162092 - use of local host IP is in test
        let input_3 = "127.0.0.1.1"; // DevSkim: ignore DS162092 - use of local host IP is in test

        // act
        let result_0 = parse_ipv4_address(input_0);
        let result_1 = parse_ipv4_address(input_1);
        let result_2 = parse_ipv4_address(input_2);
        let result_3 = parse_ipv4_address(input_3);

        // assert
        assert_eq!(result_0, Ok(("", "127.0.0.1"))); // DevSkim: ignore DS162092 - use of local host IP is in test
        assert_eq!(result_1, Ok(("", "127")));
        assert_eq!(result_2, Ok((" example.com", "127.0.0.1"))); // DevSkim: ignore DS162092 - use of local host IP is in test
        assert_eq!(result_3, Ok((".1", "127.0.0.1")));
    }

    fn arb_ipv6_address() -> impl Strategy<Value = String> {
        (0u8..1).prop_map(|_| faker::internet::en::IPv6().fake::<String>())
    }

    #[test]
    fn parse_ipv4_mapped_ipv6_address_parses_valid_address() {
        // arrange
        let input_0 = "::ffff:192.0.2.128";

        // act
        let result_0 = parse_ipv4_mapped_ipv6_address(input_0);

        // assert
        assert_eq!(result_0, Ok(("", "::ffff:192.0.2.128")));
    }

    #[test]
    fn parse_ipv4_mapped_ipv6_address_returns_error_for_valid_ipv4_mapped_ipv6_address_with_non_compressed_ipv6_prefix()
     {
        // arrange
        let input = "0:0:0:0:0:ffff:192.0.2.128";

        // act
        let result = parse_ipv4_mapped_ipv6_address(input);

        // assert
        assert_eq!(
            result,
            Err(nom::Err::Error(nom::error::Error {
                input: "0:0:0:0:0:ffff:192.0.2.128",
                code: nom::error::ErrorKind::Tag
            }))
        );
    }

    proptest! {
       #[test]
       fn parse_ipv6_address_parses_valid_address_proptest(
           ipv6_address in arb_ipv6_address()
       ) {
            // arrange
            // act
            let result = parse_ipv6_address(&ipv6_address);

            // assert
            prop_assert_eq!(result, Ok(("", ipv6_address.as_str())));
        }
    }

    #[test]
    fn parse_ipv6_address_parses_valid_ipv6_address() {
        // arrange
        let input_0 = "aaaa:bbbb:cccc:dddd:eeee:ffff:0000:1111";
        let input_1 = "A:B:C:D:E:F:0:1 something else";
        let input_2 = "::";
        let input_3 = "::aaaa";
        let input_4 = "::aaaa:aaaa:aaaa:aaaa:aaaa:aaaa";
        let input_5 = "aaaa::";
        let input_6 = "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa::";
        let input_7 = "aaaa::bbbb";
        let input_8 = "aaaa:aaaa:aaaa:aaaa:aaaa::bbbb";
        let input_9 = "1234::1";

        // act
        let result_0 = parse_ipv6_address(input_0);
        let result_1 = parse_ipv6_address(input_1);
        let result_2 = parse_ipv6_address(input_2);
        let result_3 = parse_ipv6_address(input_3);
        let result_4 = parse_ipv6_address(input_4);
        let result_5 = parse_ipv6_address(input_5);
        let result_6 = parse_ipv6_address(input_6);
        let result_7 = parse_ipv6_address(input_7);
        let result_8 = parse_ipv6_address(input_8);
        let result_9 = parse_ipv6_address(input_9);

        // assert
        assert_eq!(
            result_0,
            Ok(("", "aaaa:bbbb:cccc:dddd:eeee:ffff:0000:1111"))
        );
        assert_eq!(result_1, Ok((" something else", "A:B:C:D:E:F:0:1")));
        assert_eq!(result_2, Ok(("", "::")));
        assert_eq!(result_3, Ok(("", "::aaaa")));
        assert_eq!(result_4, Ok(("", "::aaaa:aaaa:aaaa:aaaa:aaaa:aaaa")));
        assert_eq!(result_5, Ok(("", "aaaa::")));
        assert_eq!(result_6, Ok(("", "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa::")));
        assert_eq!(result_7, Ok(("", "aaaa::bbbb")));
        assert_eq!(result_8, Ok(("", "aaaa:aaaa:aaaa:aaaa:aaaa::bbbb")));
        assert_eq!(result_9, Ok(("", "1234::1")));
    }

    #[test]
    fn parse_ipv6_address_returns_error_for_invalid_ipv6_address() {
        // arrange
        let input_0 = "z:a:b:c:d:e::";

        // needs eight hexadectets and `::` cannot compress a single hexadectet
        let input_1 = "a:b:c:d:e:f:0::";

        // act
        let result_0 = parse_ipv6_address(input_0);
        let result_1 = parse_ipv6_address(input_1);

        // assert
        assert_eq!(
            result_0,
            Err(nom::Err::Error(nom::error::Error {
                input: "z:a:b:c:d:e::",
                code: nom::error::ErrorKind::TakeWhileMN
            }))
        );
        assert_eq!(
            result_1,
            Err(nom::Err::Error(nom::error::Error {
                input: ":",
                code: nom::error::ErrorKind::TakeWhileMN
            }))
        );
    }

    #[test]
    fn parse_hostname_parses_valid_hostnames() {
        // arrange
        let input_0 = "example.com";
        let input_1 = "sub.example.com";
        let input_2 = "sub-domain.example.com";
        let input_3 = "sub_domain.example.com";

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
        let input_0 = "com";
        let input_1 = "# some annotation";

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
        let input_0 = "example.com";
        let input_1 = "example.com # some annotation";

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
        let input_0 = "127.0.0.1 example.com"; // DevSkim: ignore DS162092 - use of local host IP is in test
        let input_1 = "1234::1 example.com";

        // act
        let result_0 = parse_hostfile_line(input_0);
        let result_1 = parse_hostfile_line(input_1);

        // assert
        assert_eq!(result_0, Some("example.com"));
        assert_eq!(result_1, Some("example.com"));
    }

    #[test]
    fn parse_hostfile_line_returns_none_for_invalid_input() {
        // arrange
        let input_0 = "127.0.0.1.1 example.com"; // DevSkim: ignore DS162092 - use of local host IP is in test

        // needs eight hexadectets and `::` cannot compress a single hexadectet
        let input_1 = "1:2:3:4:5:6:7::8 example.com"; //

        // act
        let result_0 = parse_hostfile_line(input_0);
        let result_1 = parse_hostfile_line(input_1);

        // assert
        assert!(result_0.is_none());
        assert!(result_1.is_none());
    }

    #[test]
    fn parse_hostfile_line_successfully_parses_valid_ipv6_input() {
        // arrange
        let input_0 = "aaaa:bbbb:cccc:dddd:eeee:ffff:0000:1111 example.com";
        let input_1 = "a:b:c:d:e:f:0:1 example.com";
        let input_2 = "::1 example.com"; // DevSkim: ignore DS162092 - use of local host IP is in test
        let input_3 = ":: some.example.com";

        // act
        let result_0 = parse_hostfile_line(input_0);
        let result_1 = parse_hostfile_line(input_1);
        let result_2 = parse_hostfile_line(input_2);
        let result_3 = parse_hostfile_line(input_3);

        // assert
        assert_eq!(result_0, Some("example.com"));
        assert_eq!(result_1, Some("example.com"));
        assert_eq!(result_2, Some("example.com"));
        assert_eq!(result_3, Some("some.example.com"));
    }

    #[test]
    fn parse_hostfile_line_returns_error_for_invalid_ipv6_address() {
        // arrange
        let input_0 = "::: example.com";
        let input_1 = "aaaa:bbbb:cccc:dddd:eeee:ffff:0000 example.com"; // too few hexadectet
        let input_2 = "aaaa:bbbb:cccc:dddd:eeee:ffff:0000:1111:2222 example.com"; // too many
        // hexadectet

        // act
        let result_0 = parse_hostfile_line(input_0);
        let result_1 = parse_hostfile_line(input_1);
        let result_2 = parse_hostfile_line(input_2);

        // assert
        assert!(result_0.is_none());
        assert!(result_1.is_none());
        assert!(result_2.is_none());
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

    proptest! {
         #[test]
    fn parse_hostfile_line_successfully_parses_valid_ipv6_input_proptest(
        ipv6_address in arb_ipv4_address(),
        hostname in arb_domain_name()) {
        // arrange
        let line = format!("{ipv6_address} {hostname}");

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
        let hasher = ahash::RandomState::new();
        let mut hash_set: std::collections::HashSet<Host, ahash::RandomState> =
            std::collections::HashSet::with_hasher(hasher);

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
        let hasher = ahash::RandomState::new();
        let mut hash_set: std::collections::HashSet<Host, ahash::RandomState> =
            std::collections::HashSet::with_hasher(hasher);

        // act
        hostfile(input, &mut hash_set);

        // assert
        assert_eq!(hash_set.len(), 3);
        assert!(hash_set.contains(&Host::parse("example.com").unwrap()));
        assert!(hash_set.contains(&Host::parse("another-example.com").unwrap()));
        assert!(hash_set.contains(&Host::parse("final-example.com").unwrap()));
    }
}
