use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[clap(author,version,about,long_about=None)]
pub struct Cli {
    /// Config file path (default: ./blocklist-generator.toml)
    #[clap(short, long, value_parser)]
    pub config: Option<PathBuf>,

    /// (default: 3)
    #[clap(short, long, value_parser)]
    pub max_concurrent_downloads: Option<u32>,

    /// Generate Markdown documentation for app
    #[arg(long, hide = true)]
    pub markdown_help: bool,

    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,
}

impl Cli {
    /// Set logging filter level filter from user-supplied verbosity flags.
    pub fn initialise_logging(&self) {
        env_logger::Builder::new()
            .filter_level(self.verbose.log_level_filter())
            .init();
    }
}
