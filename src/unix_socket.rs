use async_proto::Protocol;

pub(crate) const PATH: &str = "/usr/local/share/midos-house/sock-status";

#[derive(clap::Subcommand, Protocol)]
pub(crate) enum Subcommand {
    BuildMw,
}
