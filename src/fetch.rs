use crate::{
    parse::{domainlist as parse_domainlist, hostfile as parse_hostfile},
    Source, SourceType,
};
use ahash::RandomState;
use futures::{Future, Stream, StreamExt};
use log::info;
use std::{collections::HashSet, error::Error};
use url::Host;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Error fetching blocklist `{url}`: only received part of the file.  The network connection may be unstable.")]
    IncompleteBody { url: String },

    #[error("Error fetching blocklist `{url}`: no response data or incomplete data.  The network connection may be unstable.")]
    FetchBody { url: String },

    #[error(
        "Error parsing fetched data for blocklist `{url}`.  It might be worth retrying later."
    )]
    FetchParse { url: String },

    #[error("Error fetching blocklist `{url}`: error requesting data.  The URL might be invalid, or there might be a network issue.")]
    FetchRequest { url: String },

    #[error("Error fetching blocklist `{url}`.  Check the URL is correct an connection is up.")]
    Fetch { url: String },
}

pub struct Client {
    client: reqwest::Client,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            client: reqwest::Client::new(),
        }
    }
}

impl Client {
    fn handle_fetch_error(url: &str, error: &reqwest::Error) -> AppError {
        log::error!("{error}");
        if error.is_body() {
            if let Some(hyper_error) = error.source().unwrap().downcast_ref::<hyper::Error>() {
                if hyper_error.is_incomplete_message() {
                    return AppError::IncompleteBody { url: url.into() };
                }
            } else {
                return AppError::FetchBody { url: url.into() };
            };
        }
        if error.is_request() {
            return AppError::FetchRequest { url: url.into() };
        }
        AppError::Fetch { url: url.into() }
    }

    async fn get_html_body(&self, url: &str) -> Result<String, AppError> {
        let response = match self.client.get(url).send().await {
            Ok(value) => value,
            Err(error) => return Err(Client::handle_fetch_error(url, &error)),
        };

        match response.text().await {
            Ok(value) => Ok(value),
            Err(_) => Err(AppError::FetchParse { url: url.into() }),
        }
    }

    pub async fn domainlist(&self, url: &str) -> Result<HashSet<Host, RandomState>, AppError> {
        let mut result = HashSet::<Host, RandomState>::default();
        info!("Fetching domainlist (stream): {url}");
        let body = self.get_html_body(url).await?;
        info!("Fetched {url}!");
        parse_domainlist(&body, &mut result);
        Ok(result)
    }

    pub async fn hostsfile(&self, url: &str) -> Result<HashSet<Host, RandomState>, AppError> {
        let mut result = HashSet::<Host, RandomState>::default();
        info!("Fetching domainlist (stream): {url}");
        let body = self.get_html_body(url).await?;
        info!("Fetched {url}!");
        parse_hostfile(&body, &mut result);
        Ok(result)
    }

    pub async fn fetch_set(
        &self,
        source: &Source<'_>,
    ) -> Result<HashSet<Host, RandomState>, AppError> {
        let Source { url, source_type } = source;
        match source_type {
            SourceType::DomainList => self.domainlist(url).await,
            SourceType::HostsFile => self.hostsfile(url).await,
        }
    }

    fn fetch_futures<'a>(
        &'a self,
        sources: &'a [Source],
    ) -> impl Stream<Item = impl Future<Output = Result<HashSet<Host, RandomState>, AppError>> + 'a>
    {
        futures::stream::iter(sources).map(move |val| self.fetch_set(val))
    }

    pub async fn domainlists(
        &self,
        sources: &[Source<'_>],
        concurrent_downloads: u32,
        set: &mut HashSet<Host, RandomState>,
    ) -> Result<(), AppError> {
        let mut result_sets = self
            .fetch_futures(sources)
            .buffer_unordered(
                concurrent_downloads
                    .try_into()
                    .expect("max concurrent download should be representable as a usize"),
            )
            .collect::<Vec<Result<HashSet<Host, RandomState>, AppError>>>()
            .await;
        for result_set in &mut result_sets {
            let set_values = result_set.as_mut().unwrap().drain();
            set.extend(set_values);
        }
        Ok(())
    }
}
