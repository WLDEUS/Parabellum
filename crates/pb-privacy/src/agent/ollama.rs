//! Minimal client of a local Ollama server (`/api/version`, `/api/tags`, `/api/pull`, `/api/chat`).
//! The server is started by the daemon on a random loopback port only for the duration of a run.

use super::classify::{self, Classification, Classifier, ClassifyInput};
use async_trait::async_trait;
use std::time::Duration;

#[derive(Clone)]
pub struct Ollama {
    base: String,
    model: String,
    http: reqwest::Client,
}

impl Ollama {
    /// `port` on 127.0.0.1. Never goes through a proxy.
    pub fn new(port: u16, model: &str) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            base: format!("http://127.0.0.1:{port}"),
            model: model.to_string(),
            http,
        })
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub async fn version(&self) -> Result<String, String> {
        let v: serde_json::Value = self
            .http
            .get(format!("{}/api/version", self.base))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        Ok(v.get("version")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .chars()
            .take(40)
            .collect())
    }

    /// Wait until the server answers (`timeout` overall).
    pub async fn wait_ready(&self, timeout: Duration) -> Result<String, String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.version().await {
                Ok(v) => return Ok(v),
                Err(e) if tokio::time::Instant::now() >= deadline => {
                    return Err(format!("serveur Ollama injoignable : {e}"))
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }

    pub async fn has_model(&self) -> Result<bool, String> {
        let v: serde_json::Value = self
            .http
            .get(format!("{}/api/tags", self.base))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        let want = if self.model.contains(':') {
            self.model.clone()
        } else {
            format!("{}:latest", self.model)
        };
        Ok(v.get("models").and_then(|m| m.as_array()).is_some_and(|l| {
            l.iter()
                .filter_map(|m| m.get("name").and_then(|n| n.as_str()))
                .any(|n| n == want)
        }))
    }

    /// Download the model (Ollama checks every layer's SHA-256 against the registry manifest).
    pub async fn pull(&self) -> Result<(), String> {
        let r = self
            .http
            .post(format!("{}/api/pull", self.base))
            .json(&serde_json::json!({ "model": self.model, "stream": false }))
            .timeout(Duration::from_secs(2 * 3600))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = r.status();
        let v: serde_json::Value = r.json().await.unwrap_or_default();
        if !status.is_success() || v.get("status").and_then(|s| s.as_str()) != Some("success") {
            return Err(format!(
                "téléchargement du modèle {} impossible : {}",
                self.model,
                v.get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or(status.as_str())
                    .chars()
                    .take(200)
                    .collect::<String>()
            ));
        }
        Ok(())
    }
}

fn nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..16].to_string()
}

#[async_trait]
impl Classifier for Ollama {
    fn name(&self) -> String {
        self.model.clone()
    }

    async fn classify(&self, input: &ClassifyInput<'_>) -> Result<Classification, String> {
        let n = nonce();
        let body = serde_json::json!({
            "model": self.model,
            "stream": false,
            "think": false,
            "keep_alive": "5m",
            "format": classify::output_schema(),
            "options": { "temperature": 0, "num_ctx": 8192, "num_predict": 300 },
            "messages": [
                { "role": "system", "content": classify::SYSTEM_PROMPT },
                { "role": "user", "content": classify::user_prompt(input, &n) }
            ]
        });
        let v: serde_json::Value = self
            .http
            .post(format!("{}/api/chat", self.base))
            .json(&body)
            .timeout(Duration::from_secs(180))
            .send()
            .await
            .map_err(|e| format!("modèle injoignable : {e}"))?
            .error_for_status()
            .map_err(|e| format!("modèle : {e}"))?
            .json()
            .await
            .map_err(|e| format!("réponse du modèle illisible : {e}"))?;
        let content = v
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .ok_or("réponse du modèle vide")?;
        classify::parse_output(content, input)
    }
}
