#![warn(clippy::all, clippy::pedantic)]

mod fetch;
mod file_system;
mod parse;

use std::{collections::HashSet, path::PathBuf};

use ahash::RandomState;
use clap::Parser;
use log::warn;
use num_format::{Locale, ToFormattedString};
use url::Host;

use fetch::Client as FetchClient;
use file_system::{
    get_blocklists_from_config_file, get_custom_blocked_names, write_blocklist_rpz_file,
    write_unbound_local_zone_file, Blocklists,
};

#[derive(Parser)]
#[clap(author,version,about,long_about=None)]
struct Cli {
    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    /// Config file path (default: ./blocklist-generator.toml)
    #[clap(short, long, value_parser)]
    config: Option<PathBuf>,
}

#[derive(Debug)]
enum SourceType {
    DomainList,
    HostsFile,
}

#[derive(Debug)]
struct Source<'a> {
    url: &'a str,
    source_type: SourceType,
}

fn sources_from_blocklists(blocklists: &Blocklists) -> Vec<Source> {
    let mut result: Vec<Source> = Vec::new();
    let Blocklists {
        hosts_file_blocklist_urls,
        domain_blocklist_urls,
    } = blocklists;

    for val in hosts_file_blocklist_urls {
        result.push(Source {
            url: val,
            source_type: SourceType::HostsFile,
        });
    }
    for val in domain_blocklist_urls {
        result.push(Source {
            url: val,
            source_type: SourceType::DomainList,
        });
    }

    result
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = &Cli::parse();
    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .init();

    let default_config_path = PathBuf::from("blocklist-generator.toml");
    let config_path = match &cli.config {
        Some(value) => value,
        None => &default_config_path,
    };

    let blocklists = get_blocklists_from_config_file(config_path);
    let sources = sources_from_blocklists(&blocklists);

    let fetch_client = FetchClient::default();
    let hasher = RandomState::new();
    let mut set: HashSet<Host, RandomState> = HashSet::with_capacity_and_hasher(524_288, hasher);
    fetch_client.domainlists(&sources, &mut set).await?;

    set.remove(&Host::parse("0.0.0.0").unwrap());
    set.remove(&Host::parse("127.0.0.1").unwrap()); // DevSkim: ignore DS162092 - use of localhost IP is for removal from generated file, and not for accessing the localhost
    set.remove(&Host::parse("255.255.255.255").unwrap());

    get_custom_blocked_names("blocked-names.txt", &mut set);

    let mut result: Vec<Host> = set.into_iter().collect();
    result.sort();

    write_blocklist_rpz_file(&result);
    write_unbound_local_zone_file(&result);

    println!("{} results", result.len().to_formatted_string(&Locale::en));
    Ok(())
}
