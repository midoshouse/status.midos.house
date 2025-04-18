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
    crate::GIT_COMMIT_HASH,
};

const BIN_PATH: &str = "/usr/local/share/midos-house/bin/midos-house";
const LIVE_REPO_PATH: &str = "/opt/git/github.com/midoshouse/midos.house/main";
const BUILD_REPO_PATH: &str = "/opt/git/github.com/midoshouse/midos.house/build";
const SELF_REPO_PATH: &str = "/opt/git/github.com/midoshouse/status.midos.house/main";

pub(crate) struct Status {
    pub(crate) running: gix::ObjectId,
    pub(crate) future: Vec<(gix::ObjectId, String, CommitStatus)>,
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
    self_repo_lock: Arc<Mutex<Instant>>,
    update: watch::Sender<gix::ObjectId>,
    self_update: watch::Sender<gix::ObjectId>,
    status: Arc<RwLock<Status>>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NewError {
    #[error(transparent)] GitHeadCommit(#[from] gix::reference::head_commit::Error),
    #[error(transparent)] GitOpen(#[from] gix::open::Error),
}

#[derive(Debug, thiserror::Error, rocket_util::Error)]
pub(crate) enum RefreshError {
    #[error(transparent)] GitDecode(#[from] gix::diff::object::decode::Error),
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
        println!("initial running commit: {running}");
        Ok(Self {
            build_repo_lock: Arc::new(Mutex::new(Instant::now())),
            self_repo_lock: Arc::new(Mutex::new(Instant::now())),
            update: watch::Sender::new(running),
            self_update: watch::Sender::new(GIT_COMMIT_HASH),
            status: Arc::new(RwLock::new(Status {
                running,
                future: Vec::default(),
            })),
        })
    }

    pub(crate) async fn refresh(&self, rate_limit: bool, block: bool) -> Result<(), RefreshError> {
        let mut last_refresh = if block {
            println!("refresh: waiting for build repo lock");
            self.build_repo_lock.0.lock().await
        } else {
            if let Ok(last_refresh) = self.build_repo_lock.0.try_lock() {
                last_refresh
            } else {
                return Ok(())
            }
        };
        if !rate_limit || last_refresh.elapsed() >= Duration::from_secs(60) {
            *last_refresh = Instant::now();
            println!("refresh: fetching midos.house");
            Command::new("git").arg("fetch").current_dir(BUILD_REPO_PATH).check("git fetch").await?; //TODO use GitHub API or gix (how?)
            let repo = gix::open(BUILD_REPO_PATH)?;
            let new_head = repo.find_reference("origin/main")?.peel_to_commit()?.id;
            let needs_update = lock!(@write status = self.status; {
                let status_latest = status.future.last().map_or(status.running, |(latest, _, _)| *latest);
                if new_head != status_latest {
                    let mut iter_commit = repo.find_commit(new_head)?;
                    let mut to_add = vec![(new_head, iter_commit.message()?.summary().to_string())];
                    loop {
                        let Ok(parent) = iter_commit.parent_ids().exactly_one() else {
                            // initial commit or merge commit; skip parents for simplicity's sake
                            break
                        };
                        if parent == status_latest { break }
                        iter_commit = parent.object()?.peel_to_commit()?;
                        to_add.push((parent.detach(), iter_commit.message()?.summary().to_string()));
                    }
                    status.future.extend(to_add.into_iter().rev().map(|(commit_hash, commit_msg)| (commit_hash, commit_msg, CommitStatus::Pending)));
                    println!("refresh: updating from {status_latest} to {new_head}");
                    true
                } else {
                    println!("refresh: already up to date at {status_latest}");
                    false
                }
            });
            if needs_update {
                self.update.send_replace(new_head);
            }
        } else {
            println!("refresh: rate limited");
        }
        drop(last_refresh);
        let mut last_refresh = if block {
            println!("refresh: waiting for self repo lock");
            self.self_repo_lock.0.lock().await
        } else {
            if let Ok(last_refresh) = self.self_repo_lock.0.try_lock() {
                last_refresh
            } else {
                return Ok(())
            }
        };
        if !rate_limit || last_refresh.elapsed() >= Duration::from_secs(60) {
            *last_refresh = Instant::now();
            println!("refresh: fetching self");
            Command::new("git").arg("fetch").current_dir(SELF_REPO_PATH).check("git fetch").await?; //TODO use GitHub API or gix (how?)
            let repo = gix::open(SELF_REPO_PATH)?;
            let new_head = repo.find_reference("origin/main")?.peel_to_commit()?.id;
            let needs_update = new_head != GIT_COMMIT_HASH;
            if needs_update {
                self.self_update.send_replace(new_head);
            }
        } else {
            println!("refresh: rate limited");
        }
        Ok(())
    }

    pub(crate) async fn status(&self) -> tokio::sync::RwLockReadGuard<'_, Status> {
        self.status.0.read().await
    }

    pub(crate) async fn run(self, mut shutdown: rocket::Shutdown) -> Result<(), RunError> {
        println!("supervisor: initializing");
        let user_dirs = UserDirs::new().ok_or(RunError::UserDirs)?;
        let next_path = user_dirs.home_dir().join("bin").join("midos-house-next");
        let mut update = self.update.subscribe();
        self.refresh(false, true).await?;
        update.mark_changed();
        let mut self_update = self.self_update.subscribe();
        self_update.mark_changed();
        loop {
            println!("supervisor: waiting for events");
            select! {
                () = &mut shutdown => {
                    println!("supervisor: shutdown requested by rocket");
                    break
                }
                () = sleep(Duration::from_secs(24 * 60 * 60)) => {
                    println!("supervisor: no events after 1 hour, requesting refresh");
                    self.refresh(true, true).await?;
                }
                res = update.changed() => {
                    println!("supervisor: got update notification");
                    let () = res.expect("all update senders dropped");
                    let old_head = gix::open(LIVE_REPO_PATH)?.head_commit()?.id; //TODO once newer commits can be built during prepare-stop, this should be whichever version is at next_path, using this as fallback
                    let needs_update = lock!(last_refresh = self.build_repo_lock; {
                        Command::new("git").arg("pull").current_dir(BUILD_REPO_PATH).check("git pull").await?; //TODO use gix (how?)
                        let new_head = gix::open(BUILD_REPO_PATH)?.head_commit()?.id;
                        if new_head != old_head {
                            lock!(@write status = self.status; if let Some(idx) = status.future.iter().position(|(iter_commit, _, _)| *iter_commit == new_head) {
                                status.future[idx].2 = CommitStatus::Build;
                                for idx in 0..idx {
                                    status.future[idx].2 = CommitStatus::Skipped;
                                }
                            });
                            //TODO rustup
                            println!("supervisor: building {new_head}");
                            Command::new(user_dirs.home_dir().join(".cargo").join("bin").join("cargo")).arg("build").arg("--release").arg("--target=x86_64-unknown-linux-musl").current_dir(BUILD_REPO_PATH).check("cargo build").await?;
                            fs::rename(Path::new(BUILD_REPO_PATH).join("target").join("x86_64-unknown-linux-musl").join("release").join("midos-house"), &next_path).await?;
                            Some(new_head)
                        } else {
                            None
                        }
                    });
                    if let Some(new_head) = needs_update {
                        println!("supervisor: updating to {new_head}");
                        if Command::new("/usr/bin/systemctl").arg("is-active").arg("midos-house").status().await.at_command("systemctl is-active")?.success() {
                            lock!(@write status = self.status; if let Some(idx) = status.future.iter().position(|(iter_commit, _, _)| *iter_commit == new_head) {
                                status.future[idx].2 = CommitStatus::PrepareStop;
                            });
                            // intentionally not checking exit status as prepare-stop crashing is also a good reason to restart Mido's House
                            //TODO allow building newer commits during prepare-stop
                            println!("supervisor: preparing to stop");
                            Command::new(BIN_PATH).arg("prepare-stop").status().await.at_command("midos-house prepare-stop")?;
                        }
                        lock!(@write status = self.status; if let Some(idx) = status.future.iter().position(|(iter_commit, _, _)| *iter_commit == new_head) {
                            status.future[idx].2 = CommitStatus::Deploy;
                        });
                        println!("supervisor: stopping old version");
                        Command::new("sudo").arg("/usr/bin/systemctl").arg("stop").arg("midos-house").check("systemctl stop").await?;
                        println!("supervisor: pulling git repo");
                        Command::new("git").arg("pull").current_dir(LIVE_REPO_PATH).check("git pull").await?; //TODO use gix (how?)
                        println!("supervisor: replacing binary");
                        Command::new("chmod").arg("+x").arg(&next_path).check("chmod").await?;
                        fs::rename(&next_path, BIN_PATH).await?;
                        println!("supervisor: starting new version");
                        Command::new("sudo").arg("/usr/bin/systemctl").arg("start").arg("midos-house").check("systemctl start").await?;
                        println!("supervisor: update completed");
                        lock!(@write status = self.status; {
                            status.running = new_head;
                            if let Some(idx) = status.future.iter().position(|(iter_commit, _, _)| *iter_commit == new_head) {
                                status.future.drain(..=idx);
                            }
                        });
                    } else {
                        println!("supervisor: no update needed");
                    }
                }
                res = self_update.changed() => {
                    println!("supervisor: got self-update notification");
                    let () = res.expect("all self-update senders dropped");
                    let old_head = GIT_COMMIT_HASH;
                    let needs_update = lock!(last_refresh = self.self_repo_lock; {
                        Command::new("git").arg("pull").current_dir(SELF_REPO_PATH).check("git pull").await?; //TODO use gix (how?)
                        let new_head = gix::open(SELF_REPO_PATH)?.head_commit()?.id;
                        if new_head != old_head {
                            //TODO rustup
                            println!("supervisor: building self {new_head}");
                            Command::new(user_dirs.home_dir().join(".cargo").join("bin").join("cargo")).arg("install-update").arg("--all").arg("--git").check("cargo install-update").await?;
                            Some(new_head)
                        } else {
                            None
                        }
                    });
                    if let Some(new_head) = needs_update {
                        println!("supervisor: pulling own git repo");
                        lock!(last_refresh = self.self_repo_lock; {
                            Command::new("git").arg("pull").current_dir(SELF_REPO_PATH).check("git pull").await?; //TODO use gix (how?)
                        });
                        println!("supervisor: updating self to {new_head}");
                        Command::new("/usr/bin/systemctl").arg("restart").arg("mhstatus").spawn().at_command("systemctl restart")?;
                        println!("supervisor: notifying rocket to shut down");
                        shutdown.notify();
                        println!("supervisor: exiting for self-restart");
                        break
                    } else {
                        println!("supervisor: no self-update needed");
                    }
                }
            }
        }
        Ok(())
    }
}
