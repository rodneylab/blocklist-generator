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
    #[error(
        "Error fetching blocklist `{url}`: only received part of the file.  The network \
        connection may be unstable."
    )]
    IncompleteBody { url: String },

    #[error(
        "Error fetching blocklist `{url}`: no response data or incomplete data.  The network \
        connection may be unstable."
    )]
    FetchBody { url: String },

    #[error(
        "Error parsing fetched data for blocklist `{url}`.  It might be worth retrying later."
    )]
    FetchParse { url: String },

    #[error(
        "Error fetching blocklist `{url}`: error requesting data.  The URL might be invalid, or \
            there might be a network issue."
    )]
    FetchRequest { url: String },

    #[error(
        "Error fetching blocklist `{url}`.  Check the URL is correct and the connection is up."
    )]
    Fetch { url: String },
}

pub struct Client {
    client: reqwest::Client,
}

impl Default for Client {
    fn default() -> Self {
        Client::new(None)
    }
}

impl Client {
    /// Initialise client optionally supplying the timeout for request.  `None` means no timeout.
    fn new(timeout: Option<std::time::Duration>) -> Self {
        if let Some(value) = timeout {
            Client {
                client: reqwest::ClientBuilder::new()
                    .timeout(value)
                    .build()
                    .expect("Reqwest builder should be able to initialise itself"),
            }
        } else {
            Client {
                client: reqwest::Client::new(),
            }
        }
    }

    fn handle_fetch_error(url: &str, error: &reqwest::Error) -> AppError {
        log::error!("{error}");
        if error.is_body() {
            if let Some(hyper_error) = error.source().unwrap().downcast_ref::<hyper::Error>() {
                if hyper_error.is_incomplete_message() {
                    return AppError::IncompleteBody { url: url.into() };
                }
            } else {
                return AppError::FetchBody { url: url.into() };
            }
        }
        if error.is_request() {
            return AppError::FetchRequest { url: url.into() };
        }
        AppError::Fetch { url: url.into() }
    }

    async fn get_text_body(&self, url: &str) -> Result<String, AppError> {
        let response = match self.client.get(url).send().await {
            Ok(value) => match value.error_for_status() {
                Ok(ok_response_value) => ok_response_value,
                Err(error) => return Err(Client::handle_fetch_error(url, &error)),
            },
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
        let body = self.get_text_body(url).await?;
        info!("Fetched {url}.");
        parse_domainlist(&body, &mut result);
        Ok(result)
    }

    pub async fn hostsfile(&self, url: &str) -> Result<HashSet<Host, RandomState>, AppError> {
        let mut result = HashSet::<Host, RandomState>::default();
        info!("Fetching domainlist (stream): {url}");
        let body = self.get_text_body(url).await?;
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use ahash::RandomState;
    use url::Host;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::{fetch::Client, Source, SourceType};

    #[tokio::test]
    async fn domainlist_contacts_remote_server() {
        // arrange
        let mock_remote_server = MockServer::start().await;
        let mock_remote_uri = format!("{}/domainlist", mock_remote_server.uri());
        Mock::given(path("/domainlist"))
            .and(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("# comment\n\nexample.com\nanother.example.com\n"),
            )
            .expect(1)
            .mount(&mock_remote_server)
            .await;
        let client = Client::default();

        // act
        let outcome = client.domainlist(&mock_remote_uri).await.unwrap();

        // assert
        assert_eq!(outcome.len(), 2);
        assert!(outcome.contains(&Host::parse("example.com").unwrap()));
        assert!(outcome.contains(&Host::parse("another.example.com").unwrap()));
    }

    #[tokio::test]
    async fn domainlist_returns_error_if_remote_server_is_unreachable() {
        // arrange
        let client = Client::new(Some(std::time::Duration::from_secs(1)));

        // act
        let outcome = client
            .domainlist("https://0.0.0.0/does-not-exist")
            .await
            .unwrap_err();

        // assert
        assert_eq!(
            format!("{outcome}"),
            "Error fetching blocklist `https://0.0.0.0/does-not-exist`: error requesting data.  \
                The URL might be invalid, or there might be a network issue."
        );
    }

    #[tokio::test]
    async fn domainlist_returns_error_if_page_not_found() {
        // arrange
        let mock_remote_server = MockServer::start().await;
        let mock_remote_uri = format!("{}/domainlist", mock_remote_server.uri());
        Mock::given(path("/domainlist"))
            .and(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .expect(1)
            .mount(&mock_remote_server)
            .await;
        let client = Client::default();

        // act
        let outcome = client.domainlist(&mock_remote_uri).await.unwrap_err();

        // assert
        assert_eq!(
            format!("{outcome}"),
            format!(
                "Error fetching blocklist `{mock_remote_uri}`.  Check the URL is correct and the \
      connection is up."
            )
        );
    }

    #[tokio::test]
    async fn hostsfile_contacts_remote_server() {
        // arrange
        let mock_remote_server = MockServer::start().await;
        let mock_remote_uri = format!("{}/hosts", mock_remote_server.uri());
        Mock::given(path("/hosts"))
            .and(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "# comment\n\n0.0.0.0 example.com\n0.0.0.0\tanother.example.com\n",
            ))
            .expect(1)
            .mount(&mock_remote_server)
            .await;
        let client = Client::default();

        // act
        let outcome = client.hostsfile(&mock_remote_uri).await.unwrap();

        // assert
        assert_eq!(outcome.len(), 2);
        assert!(outcome.contains(&Host::parse("example.com").unwrap()));
        assert!(outcome.contains(&Host::parse("another.example.com").unwrap()));
    }

    #[tokio::test]
    async fn hostsfile_returns_error_when_remote_server_returns_a_server_error() {
        // arrange
        let mock_remote_server = MockServer::start().await;
        let mock_remote_uri = format!("{}/hosts", mock_remote_server.uri());
        Mock::given(path("/hosts"))
            .and(method("GET"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Something went wrong!"))
            .expect(1)
            .mount(&mock_remote_server)
            .await;
        let client = Client::default();

        // act
        let outcome = client.hostsfile(&mock_remote_uri).await.unwrap_err();

        // assert
        assert_eq!(
            format!("{outcome}"),
            format!(
                "Error fetching blocklist `{mock_remote_uri}`.  Check the URL is correct and the \
      connection is up."
            )
        );
    }

    #[tokio::test]
    async fn fetch_set_contacts_remote_servers() {
        // arrange
        let mock_remote_server = MockServer::start().await;
        let mock_remote_uri_1 = format!("{}/hosts", mock_remote_server.uri());
        Mock::given(path("/hosts"))
            .and(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "# comment\n\n0.0.0.0 example.com\n0.0.0.0\tanother.example.com\n",
            ))
            .expect(1)
            .mount(&mock_remote_server)
            .await;
        let client = Client::default();
        let source = Source {
            url: &mock_remote_uri_1,
            source_type: SourceType::HostsFile,
        };

        // act
        let outcome = client.fetch_set(&source).await.unwrap();

        // assert
        assert_eq!(outcome.len(), 2);
        assert!(outcome.contains(&Host::parse("example.com").unwrap()));
        assert!(outcome.contains(&Host::parse("another.example.com").unwrap()));
    }

    #[tokio::test]
    async fn domainlists_compiles_result_set() {
        // arrange
        let mock_remote_server = MockServer::start().await;
        let mock_remote_uri_1 = format!("{}/hosts_a", mock_remote_server.uri());
        let mock_remote_uri_2 = format!("{}/domainlist", mock_remote_server.uri());
        let mock_remote_uri_3 = format!("{}/hosts_b", mock_remote_server.uri());
        Mock::given(path("/hosts_a"))
            .and(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "# comment\n\n0.0.0.0 example.com\n0.0.0.0\tanother.example.com\n",
            ))
            .expect(1)
            .mount(&mock_remote_server)
            .await;
        Mock::given(path("/domainlist"))
            .and(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("# comment\nexample.com\nrepeat.example.com\n"),
            )
            .expect(1)
            .mount(&mock_remote_server)
            .await;
        Mock::given(path("/hosts_b"))
            .and(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "# comment\n\n0.0.0.0 yet.another.example.com\n0.0.0.0\trepeat.example.com\n",
            ))
            .expect(1)
            .mount(&mock_remote_server)
            .await;
        let client = Client::default();
        let sources = [
            Source {
                url: &mock_remote_uri_1,
                source_type: SourceType::HostsFile,
            },
            Source {
                url: &mock_remote_uri_2,
                source_type: SourceType::DomainList,
            },
            Source {
                url: &mock_remote_uri_3,
                source_type: SourceType::HostsFile,
            },
        ];
        let max_concurrent_downloads = 3;

        // act
        let hasher = RandomState::new();
        let mut result: HashSet<Host, RandomState> = HashSet::with_hasher(hasher);
        let outcome = client
            .domainlists(&sources, max_concurrent_downloads, &mut result)
            .await;

        // assert
        assert!(outcome.is_ok());
        assert_eq!(result.len(), 4);
        assert!(result.contains(&Host::parse("example.com").unwrap()));
        assert!(result.contains(&Host::parse("another.example.com").unwrap()));
        assert!(result.contains(&Host::parse("repeat.example.com").unwrap()));
        assert!(result.contains(&Host::parse("yet.another.example.com").unwrap()));
    }
}
