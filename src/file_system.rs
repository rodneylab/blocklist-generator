use std::{
    collections::HashSet,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use ahash::RandomState;
use askama::Template;
use humansize::{format_size, DECIMAL};
use log::{error, info};
use serde::Deserialize;
use url::Host;

use crate::parse::domainlist as parse_domainlist;

#[derive(Deserialize)]
pub struct Blocklists {
    pub hosts_file_blocklist_urls: Vec<String>,
    pub domain_blocklist_urls: Vec<String>,
}

#[derive(Deserialize)]
struct Config {
    blocklists: Blocklists,
}

pub fn get_blocklists_from_config_file<P: AsRef<Path>>(config_file_path: P) -> Blocklists {
    let config_file_content =
        fs::read_to_string(config_file_path).expect("Unable to open or read config file");
    let config: Config = toml::from_str(&config_file_content).expect("Unable to parse TOML config");

    let Config { blocklists } = config;

    blocklists
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
