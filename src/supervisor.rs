use {
    std::{
        path::Path,
        sync::Arc,
        time::Duration,
    },
    directories::UserDirs,
    itertools::Itertools as _,
    log_lock::*,
    tokio::{
        process::Command,
        select,
        sync::watch,
        time::{
            Instant,
            sleep,
        },
    },
    wheel::{
        fs,
        traits::{
            AsyncCommandOutputExt as _,
            IoResultExt as _,
        },
    },
};

const BIN_PATH: &str = "/usr/local/share/midos-house/bin/midos-house";
const LIVE_REPO_PATH: &str = "/opt/git/github.com/midoshouse/midos.house/main";
const BUILD_REPO_PATH: &str = "/opt/git/github.com/midoshouse/midos.house/build";

pub(crate) struct Status {
    pub(crate) running: gix::ObjectId,
    pub(crate) future: Vec<(gix::ObjectId, CommitStatus)>,
}

pub(crate) enum CommitStatus {
    Pending,
    Skipped,
    Build,
    PrepareStop,
    Deploy,
}

#[derive(Clone)]
pub(crate) struct Supervisor {
    build_repo_lock: Arc<Mutex<Instant>>,
    update: watch::Sender<gix::ObjectId>,
    status: Arc<RwLock<Status>>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NewError {
    #[error(transparent)] GitHeadCommit(#[from] gix::reference::head_commit::Error),
    #[error(transparent)] GitOpen(#[from] gix::open::Error),
}

#[derive(Debug, thiserror::Error, rocket_util::Error)]
pub(crate) enum RefreshError {
    #[error(transparent)] GitFind(#[from] gix::object::find::existing::Error),
    #[error(transparent)] GitFindWithConversion(#[from] gix::object::find::existing::with_conversion::Error),
    #[error(transparent)] GitFindReference(#[from] gix::reference::find::existing::Error),
    #[error(transparent)] GitHeadCommit(#[from] gix::reference::head_commit::Error),
    #[error(transparent)] GitOpen(#[from] gix::open::Error),
    #[error(transparent)] GitPeel(#[from] gix::object::peel::to_kind::Error),
    #[error(transparent)] GitPeelReference(#[from] gix::reference::peel::to_kind::Error),
    #[error(transparent)] Wheel(#[from] wheel::Error),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RunError {
    #[error(transparent)] GitFindReference(#[from] gix::reference::find::existing::Error),
    #[error(transparent)] GitHeadCommit(#[from] gix::reference::head_commit::Error),
    #[error(transparent)] GitOpen(#[from] gix::open::Error),
    #[error(transparent)] GitPeelReference(#[from] gix::reference::peel::to_kind::Error),
    #[error(transparent)] Refresh(#[from] RefreshError),
    #[error(transparent)] Wheel(#[from] wheel::Error),
    #[error("failed to access user directories")]
    UserDirs,
}

impl Supervisor {
    pub(crate) fn new() -> Result<Self, NewError> {
        let running = gix::open(LIVE_REPO_PATH)?.head_commit()?.id;
        Ok(Self {
            build_repo_lock: Arc::new(Mutex::new(Instant::now())),
            update: watch::Sender::new(running),
            status: Arc::new(RwLock::new(Status {
                running,
                future: Vec::default(),
            })),
        })
    }

    pub(crate) async fn refresh(&self, rate_limit: bool) -> Result<(), RefreshError> {
        lock!(last_refresh = self.build_repo_lock; {
            if !rate_limit || last_refresh.elapsed() >= Duration::from_secs(60) {
                *last_refresh = Instant::now();
                Command::new("git").arg("fetch").current_dir(BUILD_REPO_PATH).check("git fetch").await?; //TODO use GitHub API or gix (how?)
                let repo = gix::open(BUILD_REPO_PATH)?;
                let new_head = repo.find_reference("origin/main")?.peel_to_commit()?.id;
                let needs_update = lock!(@write status = self.status; {
                    let status_latest = status.future.last().map_or(status.running, |(latest, _)| *latest);
                    if new_head != status_latest {
                        let mut to_add = vec![new_head];
                        let mut iter_commit = repo.find_commit(new_head)?;
                        loop {
                            let Ok(parent) = iter_commit.parent_ids().exactly_one() else {
                                // initial commit or merge commit; skip parents for simplicity's sake
                                break
                            };
                            if parent == status_latest { break }
                            to_add.push(parent.detach());
                            iter_commit = parent.object()?.peel_to_commit()?;
                        }
                        status.future.extend(to_add.into_iter().rev().map(|commit_hash| (commit_hash, CommitStatus::Pending)));
                        true
                    } else {
                        false
                    }
                });
                if needs_update {
                    self.update.send_replace(new_head);
                }
            }
        });
        Ok(())
    }

    pub(crate) async fn status(&self) -> tokio::sync::RwLockReadGuard<'_, Status> {
        self.status.0.read().await
    }

    pub(crate) async fn run(self, mut shutdown: rocket::Shutdown) -> Result<(), RunError> {
        let user_dirs = UserDirs::new().ok_or(RunError::UserDirs)?;
        let next_path = user_dirs.home_dir().join("bin").join("midos-house-next");
        let mut update = self.update.subscribe();
        self.refresh(false).await?;
        update.mark_changed();
        loop {
            select! {
                () = &mut shutdown => break,
                () = sleep(Duration::from_secs(24 * 60 * 60)) => self.refresh(true).await?,
                res = update.changed() => {
                    let () = res.expect("all update senders dropped");
                    let needs_update = lock!(last_refresh = self.build_repo_lock; {
                        let old_head = gix::open(BUILD_REPO_PATH)?.head_commit()?.id;
                        Command::new("git").arg("pull").current_dir(BUILD_REPO_PATH).check("git pull").await?; //TODO use gix (how?)
                        let new_head = gix::open(BUILD_REPO_PATH)?.head_commit()?.id;
                        if new_head != old_head {
                            lock!(@write status = self.status; if let Some(idx) = status.future.iter().position(|(iter_commit, _)| *iter_commit == new_head) {
                                status.future[idx].1 = CommitStatus::Build;
                                for idx in 0..idx {
                                    status.future[idx].1 = CommitStatus::Skipped;
                                }
                            });
                            //TODO rustup
                            Command::new(user_dirs.home_dir().join(".cargo").join("bin").join("cargo")).arg("build").arg("--release").arg("--target=x86_64-unknown-linux-musl").current_dir(BUILD_REPO_PATH).check("cargo build").await?;
                            fs::rename(Path::new(BUILD_REPO_PATH).join("target").join("x86_64-unknown-linux-musl").join("release").join("midos-house"), &next_path).await?;
                            Some(new_head)
                        } else {
                            None
                        }
                    });
                    if let Some(new_head) = needs_update {
                        if Command::new("/usr/bin/systemctl").arg("is-active").arg("midos-house").status().await.at_command("systemctl is-active")?.success() {
                            lock!(@write status = self.status; if let Some(idx) = status.future.iter().position(|(iter_commit, _)| *iter_commit == new_head) {
                                status.future[idx].1 = CommitStatus::PrepareStop;
                            });
                            // intentionally not checking exit status as prepare-stop crashing is also a good reason to restart Mido's House
                            //TODO allow building newer commits during prepare-stop
                            Command::new(BIN_PATH).arg("prepare-stop").status().await.at_command("midos-house prepare-stop")?;
                        }
                        lock!(@write status = self.status; if let Some(idx) = status.future.iter().position(|(iter_commit, _)| *iter_commit == new_head) {
                            status.future[idx].1 = CommitStatus::Deploy;
                        });
                        Command::new("sudo").arg("/usr/bin/systemctl").arg("stop").arg("midos-house").check("systemctl stop").await?;
                        Command::new("git").arg("pull").current_dir(LIVE_REPO_PATH).check("git pull").await?; //TODO use gix (how?)
                        Command::new("chmod").arg("+x").arg(&next_path).check("chmod").await?;
                        fs::rename(&next_path, BIN_PATH).await?;
                        Command::new("sudo").arg("/usr/bin/systemctl").arg("start").arg("midos-house").check("systemctl start").await?;
                        lock!(@write status = self.status; {
                            status.running = new_head;
                            if let Some(idx) = status.future.iter().position(|(iter_commit, _)| *iter_commit == new_head) {
                                status.future.drain(..idx);
                            }
                        });
                    }
                }
            }
        }
        Ok(())
    }
}
