use std::{
    collections::HashSet,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use ahash::RandomState;
use anyhow::Context;
use askama::Template;
use humansize::{format_size, DECIMAL};
use log::{error, info};
use serde::Deserialize;
use url::Host;

use crate::parse::domainlist as parse_domainlist;

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Blocklists {
    pub hosts_file_blocklist_urls: Vec<String>,
    pub domain_blocklist_urls: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Filters {
    pub allowed_names: Option<Vec<String>>,

    #[cfg_attr(not(test), expect(dead_code))]
    pub blocked_names: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct Config {
    pub blocklists: Blocklists,
    pub filters: Option<Filters>,
}

pub fn get_config_from_file<P: AsRef<Path>>(config_file_path: P) -> anyhow::Result<Config> {
    let config_file_content = fs::read_to_string(&config_file_path).with_context(|| {
        format!(
            "Failed to open or read config file `{}`",
            config_file_path.as_ref().display()
        )
    })?;

    match toml::from_str(&config_file_content) {
        Ok(value) => Ok(value),
        Err(_) => anyhow::bail!(
            "Failed to parse config file `{}`.  Check it is valid.",
            config_file_path.as_ref().display()
        ),
    }
}

pub fn get_custom_blocked_names<P: AsRef<Path>>(
    blocked_names_path: P,
    set: &mut HashSet<Host, RandomState>,
) {
    let blocked_names_display_path = blocked_names_path.as_ref().display().to_string();
    let blocked_names_content = if let Ok(value) = fs::read_to_string(blocked_names_path) {
        Some(value)
    } else {
        info!("No custom blocked names file found at `{blocked_names_display_path}.",);
        None
    };
    if let Some(value) = blocked_names_content {
        parse_domainlist(&value, set);
    };
}

#[derive(Template)]
#[template(escape = "none", path = "blocklist.rpz")]
struct BlocklistRPZTemplate<'a> {
    domains: &'a str,
}

fn domain_to_blocklist_rpz_domain(host: &Host) -> String {
    let domain = host.to_string();
    format!("{domain}\tCNAME\t.\n*.{domain}\tCNAME\t.\n")
}

fn domain_to_unbound_local_zone(host: &Host) -> String {
    let domain = host.to_string();
    format!("local-zone: \"{domain}\" always_nxdomain\n")
}

fn write_to_file<P: AsRef<Path>>(content: &str, output_path: &P) {
    let output_display_path = output_path.as_ref().display().to_string();
    let Ok(mut outfile) = File::create(output_path) else {
        error!("Unable to create output file");
        panic!("Error creating output file {output_display_path}")
    };
    if outfile.write_all(content.as_bytes()).is_err() {
        error!("Unable to write to output file {output_display_path}");
        panic!("Error writing to output file");
    }
    info!("Wrote data to file: {output_display_path}");
}

fn print_output_file_metadata<P: AsRef<Path>>(output_path: &P) {
    if let Ok(value) = fs::metadata(output_path) {
        let bytes = value.len();
        let display_bytes = format_size(bytes, DECIMAL);
        let display_path = output_path.as_ref().display();
        std::println!("Written {display_bytes} to {display_path}");
    }
}

pub fn write_domain_blocklist_file(blocklist_domains: &[Host]) {
    let domains = blocklist_domains
        .iter()
        .fold(String::new(), |mut acc, val| {
            acc.push_str(&val.to_string());
            acc.push('\n');
            acc
        });
    let output_path = PathBuf::from("./domain-blocklist.txt");
    write_to_file(&domains, &output_path);
    print_output_file_metadata(&output_path);
}

pub fn write_blocklist_rpz_file(blocklist_domains: &[Host]) {
    let domains = blocklist_domains
        .iter()
        .fold(String::new(), |mut acc, val| {
            acc.push_str(&domain_to_blocklist_rpz_domain(val));
            acc
        });
    let template = BlocklistRPZTemplate { domains: &domains };
    let file_content = template
        .render()
        .expect("Unexpected error rendering template");
    let output_path = PathBuf::from("./blocklist.rpz");
    write_to_file(&file_content, &output_path);
    print_output_file_metadata(&output_path);
}

pub fn write_unbound_local_zone_file(blocklist_domains: &[Host]) {
    let output_path = PathBuf::from("./zone-block-general.conf");
    let file_content = blocklist_domains
        .iter()
        .fold(String::new(), |mut acc, val| {
            acc.push_str(&domain_to_unbound_local_zone(val));
            acc
        });
    write_to_file(&file_content, &output_path);
    print_output_file_metadata(&output_path);
}

#[cfg(test)]
mod tests {
    use assert_fs::fixture::{FileWriteStr, PathChild};

    use crate::file_system::get_config_from_file;

    #[test]
    fn get_config_from_file_successfully_parses_valid_file() {
        let config_content = r#"[blocklists]
hosts_file_blocklist_urls = [
  "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts;showintro=0",
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
  "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
  "https://reddestdream.github.io/Projects/MinimalHosts/etc/MinimalHostsBlocker/minimalhosts",
]
domain_blocklist_urls = [
  "https://quidsup.net/notrack/blocklist.php?download=annoyancedomains",
  "https://quidsup.net/notrack/blocklist.php?download=malwaredomains",
  "https://quidsup.net/notrack/blocklist.php?download=trackersdomains",
  "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
  "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
  "https://v.firebog.net/hosts/AdguardDNS.txt",
  "https://v.firebog.net/hosts/Easyprivacy.txt",
]

[filters]
allowed_names = [
  "0.0.0.0",
  "127.0.0.1",
  "255.255.255.255",
  "example.com",
  "another.example.com",
]
"#;
        let temp_dir = assert_fs::TempDir::new().unwrap();
        let _ = temp_dir
            .child("blocklist-generator.toml")
            .write_str(config_content);
        let config_path = temp_dir.join("blocklist-generator.toml");

        // act
        let outcome = get_config_from_file(config_path).unwrap();

        // assert
        insta::assert_json_snapshot!(outcome);
    }

    #[test]
    fn get_config_from_file_returns_error_on_config_file_system_error() {
        let temp_dir = assert_fs::TempDir::new().unwrap();
        // file not created deliberately
        let config_path = temp_dir.join("does-not-exist-generator.toml");

        // act
        let outcome = get_config_from_file(&config_path).unwrap_err();

        // assert
        assert_eq!(
            format!("{outcome}"),
            format!(
                "Failed to open or read config file `{}`",
                &config_path.display()
            )
        );
        let mut chain = outcome.chain();
        assert_eq!(
            chain.next().map(|val| format!("{val}")),
            Some(format!(
                "Failed to open or read config file `{}`",
                &config_path.display()
            ))
        );
        assert_eq!(
            chain.next().map(|val| format!("{val}")),
            Some(String::from("No such file or directory (os error 2)"))
        );
        assert!(chain.next().is_none());
    }

    #[test]
    fn get_config_from_file_returns_error_on_invalid_config_file() {
        let config_content = r#"[blocklists]
hosts_file_blocklist_urls = [
  "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts;showintro=0",
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
  "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
  "https://reddestdream.github.io/Projects/MinimalHosts/etc/MinimalHostsBlocker/minimalhosts",
]
domain_blocklist_urls = [
  "https://quidsup.net/notrack/blocklist.php?download=annoyancedomains",
  "https://quidsup.net/notrack/blocklist.php?download=malwaredomains",
  "https://quidsup.net/notrack/blocklist.php?download=trackersdomains",
  "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
  "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
  "https://v.firebog.net/hosts/AdguardDNS.txt",
  "https://v.firebog.net/hosts/Easyprivacy.txt",
]

[filter"#;
        let temp_dir = assert_fs::TempDir::new().unwrap();
        let _ = temp_dir
            .child("blocklist-generator.toml")
            .write_str(config_content);
        let config_path = temp_dir.join("blocklist-generator.toml");

        // act
        let outcome = get_config_from_file(&config_path).unwrap_err();

        // assert
        assert_eq!(
            format!("{outcome}"),
            format!(
                "Failed to parse config file `{}`.  Check it is valid.",
                &config_path.display()
            )
        );
        let mut chain = outcome.chain();
        assert_eq!(
            chain.next().map(|val| format!("{val}")),
            Some(format!(
                "Failed to parse config file `{}`.  Check it is valid.",
                &config_path.display()
            ))
        );
        assert!(chain.next().is_none());
    }
}
