//! `magnetite-k8s` — a thin, read-only Kubernetes API client.
//!
//! Rather than pull in the heavy `kube` + `k8s-openapi` stack, this speaks the kube
//! REST API directly over the same hyper + rustls plumbing the rest of magnetite
//! uses (mirroring `magnetite-feed`): a bearer-authenticated HTTPS `GET` per
//! resource, parsed into the compact read models in `magnetite-core`. It lists
//! Deployments / Services / Pods and streams a pod's log tail — enough for the Web
//! UI's live cluster views. Writes (apply/scale/delete) are intentionally out of
//! scope.
//!
//! TLS trusts the server certificate without verification (a kube API server
//! presents its cluster CA, which magnetite does not hold): auth rests on the bearer
//! token over TLS, matching `magnetite-feed`'s self-signed-feed posture.

#![forbid(unsafe_code)]

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use magnetite_core::domains::k8s::model::K8sWorkloads;

mod parse;

/// A read-only client for one cluster's kube API server.
pub struct KubeClient {
    /// API server base URL, no trailing slash (e.g. `https://10.0.0.1:6443`).
    base: String,
    /// Bearer token (a service-account token with read access).
    token: String,
}

impl KubeClient {
    /// Build a client for `endpoint` authenticating with `token`.
    #[must_use]
    pub fn new(endpoint: &str, token: &str) -> Self {
        Self {
            base: endpoint.trim().trim_end_matches('/').to_string(),
            token: token.to_string(),
        }
    }

    /// `GET {base}{path}` with the bearer token, returning the raw body bytes.
    async fn get(&self, path: &str) -> Result<bytes::Bytes> {
        let uri: hyper::Uri = format!("{}{}", self.base, path)
            .parse()
            .with_context(|| format!("invalid kube URL {}{path}", self.base))?;
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(danger_client_config())
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);
        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(uri)
            .header("authorization", format!("Bearer {}", self.token))
            .header("accept", "application/json")
            .body(Empty::<bytes::Bytes>::new())?;
        let resp = client
            .request(req)
            .await
            .context("kube API request failed")?;
        let status = resp.status();
        let body = resp.into_body().collect().await?.to_bytes();
        if !status.is_success() {
            let msg = String::from_utf8_lossy(&body);
            bail!("kube API {path} returned {status}: {}", msg.trim());
        }
        Ok(body)
    }

    /// A JSON `GET` deserialized into `T`.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let body = self.get(path).await?;
        serde_json::from_slice(&body).with_context(|| format!("decoding kube response for {path}"))
    }

    /// The `/namespaces/{ns}` path segment, or empty for a cluster-wide (all
    /// namespaces) query when `namespace` is blank.
    fn ns_segment(namespace: &str) -> String {
        let ns = namespace.trim();
        if ns.is_empty() {
            String::new()
        } else {
            format!("/namespaces/{ns}")
        }
    }

    /// List Deployments, Services and Pods in `namespace` (blank = all namespaces).
    ///
    /// # Errors
    /// A request, HTTP-status or JSON-decoding failure for any of the three lists.
    pub async fn workloads(&self, namespace: &str) -> Result<K8sWorkloads> {
        let ns = Self::ns_segment(namespace);
        let deployments: parse::List<parse::Deployment> = self
            .get_json(&format!("/apis/apps/v1{ns}/deployments"))
            .await?;
        let services: parse::List<parse::Service> =
            self.get_json(&format!("/api/v1{ns}/services")).await?;
        let pods: parse::List<parse::Pod> = self.get_json(&format!("/api/v1{ns}/pods")).await?;
        Ok(K8sWorkloads {
            deployments: deployments.items.into_iter().map(Into::into).collect(),
            services: services.items.into_iter().map(Into::into).collect(),
            pods: pods.items.into_iter().map(Into::into).collect(),
        })
    }

    /// Fetch the last `tail_lines` of a pod's log (its first/only container).
    ///
    /// # Errors
    /// A request or HTTP-status failure (e.g. the pod not existing).
    pub async fn pod_logs(&self, namespace: &str, pod: &str, tail_lines: u32) -> Result<String> {
        let ns = namespace.trim();
        if ns.is_empty() {
            bail!("pod logs require a namespace");
        }
        let body = self
            .get(&format!(
                "/api/v1/namespaces/{ns}/pods/{pod}/log?tailLines={tail_lines}"
            ))
            .await?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}

/// A rustls client config that accepts any server certificate (see the module doc:
/// a kube API server presents its own cluster CA; auth rests on the bearer token).
fn danger_client_config() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth()
}

/// Certificate verifier that accepts everything (signature checks still run).
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
