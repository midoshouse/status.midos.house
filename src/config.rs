use serde::Deserialize;
#[cfg(unix)] use xdg::BaseDirectories;
#[cfg(windows)] use {
    tokio::process::Command,
    wheel::traits::IoResultExt as _,
};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Config {
    pub(crate) github_webhook_secret: String,
    pub(crate) secret_key: String,
}

impl Config {
    pub(crate) async fn load() -> Result<Self, crate::Error> {
        #[cfg(unix)] {
            if let Some(config_path) = BaseDirectories::new()?.find_config_file("midos-house.json") {
                Ok(fs::read_json(config_path).await?)
            } else {
                Err(crate::Error::MissingConfigFile)
            }
        }
        #[cfg(windows)] { // allow testing without having rust-analyzer slow down the server
            Ok(serde_json::from_slice(&Command::new("ssh").arg("midos.house").arg("cat").arg("/etc/xdg/midos-house.json").output().await.at_command("ssh")?.stdout)?)
        }
    }
}
