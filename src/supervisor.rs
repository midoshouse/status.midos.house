use {
    std::{
        borrow::Cow,
        cmp::Ordering::*,
        collections::{
            HashSet,
            VecDeque,
        },
        env,
        iter,
        path::Path,
        pin::Pin,
        process::{
            self,
            Stdio,
        },
        sync::Arc,
        time::Duration,
    },
    async_proto::{
        Protocol,
        ReadError,
        ReadErrorKind,
    },
    dir_lock::DirLock,
    directories::UserDirs,
    futures::{
        future::{
            self,
            Either,
            FutureExt as _,
        },
        stream::{
            FuturesUnordered,
            StreamExt as _,
        },
    },
    itertools::Itertools as _,
    lazy_regex::regex_captures,
    log_lock::*,
    serde::{
        Deserialize,
        Serialize,
    },
    tokio::{
        io,
        process::Command,
        select,
        sync::{
            mpsc,
            watch,
        },
        time::sleep,
    },
    wheel::{
        fs,
        traits::{
            AsyncCommandOutputExt as _,
            CommandExt as _,
            IoResultExt as _,
            SendResultExt as _,
        },
    },
    which::which,
    mhstatus::{
        OpenRoom,
        PrepareStopUpdate,
    },
    crate::GIT_COMMIT_HASH,
};
#[cfg(unix)] use {
    tokio::net::{
        UnixListener,
        UnixStream,
    },
    crate::unix_socket::{
        self,
        Subcommand,
    },
};
#[cfg(not(unix))] use tokio::io::Empty as UnixStream;
#[cfg(windows)] use directories::BaseDirs;

const BIN_PATH: &str = "/usr/local/share/midos-house/bin/midos-house";
const LIVE_REPO_PATH: &str = "/opt/git/github.com/midoshouse/midos.house/main";
const BUILD_REPO_PATH: &str = "/opt/git/github.com/midoshouse/midos.house/build";
const MW_BUILD_REPO_PATH: &str = "/opt/git/github.com/midoshouse/ootr-multiworld/build";
const SELF_REPO_PATH: &str = "/opt/git/github.com/midoshouse/status.midos.house/main";

fn rust_lock_dir() -> Cow<'static, Path> {
    #[cfg(unix)] { Cow::Borrowed(Path::new("/tmp/syncbin-startup-rust.lock")) }
    #[cfg(windows)] { Cow::Owned(BaseDirs::new().expect("could not determine home dir").data_local_dir().join("Temp").join("syncbin-startup-rust.lock")) }
}

pub(crate) struct Status {
    pub(crate) watch: watch::Sender<()>,
    pub(crate) running: gix::ObjectId,
    pub(crate) future: Vec<(gix::ObjectId, String, CommitStatus)>,
    pub(crate) self_future: Vec<(gix::ObjectId, String, SelfCommitStatus)>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub(crate) enum CommitStatus {
    Pending,
    Bundled,
    Build,
    PrepareStopInit,
    PrepareStopAcquiringMutex,
    WaitingForRooms {
        rooms: HashSet<OpenRoom>,
    },
    Deploy,
}

impl CommitStatus {
    fn is_prepare_stop(&self) -> bool {
        match self {
            Self::Bundled | Self::Build | Self::Pending => false,
            Self::PrepareStopInit | Self::PrepareStopAcquiringMutex | Self::WaitingForRooms { .. } | Self::Deploy => true,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub(crate) enum SelfCommitStatus {
    Pending,
    Bundled,
    Build,
    WaitRestart,
}

#[derive(Clone, Copy, Deserialize)]
pub(crate) enum RepoName {
    #[serde(rename = "midos.house")]
    MidosHouse,
    #[serde(rename = "status.midos.house")]
    Status,
}

#[derive(Clone)]
pub(crate) struct Supervisor {
    build_repo_lock: Arc<Mutex<()>>,
    self_repo_lock: Arc<Mutex<()>>,
    status: Arc<RwLock<Status>>,
    webhook: mpsc::Sender<RepoName>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)] DirLock(#[from] dir_lock::Error),
    #[error(transparent)] EnvJoinPaths(#[from] env::JoinPathsError),
    #[error(transparent)] GitDecode(#[from] gix::diff::object::decode::Error),
    #[error(transparent)] GitFind(#[from] gix::object::find::existing::Error),
    #[error(transparent)] GitFindReference(#[from] gix::reference::find::existing::Error),
    #[error(transparent)] GitFindWithConversion(#[from] gix::object::find::existing::with_conversion::Error),
    #[error(transparent)] GitHashDecode(#[from] gix::hash::decode::Error),
    #[error(transparent)] GitHeadCommit(#[from] gix::reference::head_commit::Error),
    #[error(transparent)] GitOpen(#[from] gix::open::Error),
    #[error(transparent)] GitPeel(#[from] gix::object::peel::to_kind::Error),
    #[error(transparent)] GitPeelReference(#[from] gix::reference::peel::to_kind::Error),
    #[error(transparent)] Read(#[from] ReadError),
    #[error(transparent)] Task(#[from] tokio::task::JoinError),
    #[error(transparent)] Utf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)] Wheel(#[from] wheel::Error),
    #[error(transparent)] Write(#[from] async_proto::WriteError),
    #[error("failed to parse version of midos-house-next")]
    NextVersion,
    #[error("failed to access user directories")]
    UserDirs,
}

impl Supervisor {
    pub(crate) async fn new() -> Result<(Self, impl FnOnce(rocket::Shutdown) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>), Error> {
        #[cfg(not(unix))]
        /// Dummy type implementing a subset of `tokio::net::UnixListener`'s API, used since `tokio::select!` doesn't support conditional compilation.
        struct UnixListener;

        #[cfg(not(unix))]
        impl UnixListener {
            async fn accept(&self) -> io::Result<(UnixStream, ())> {
                future::pending().await
            }
        }

        #[cfg(not(unix))]
        #[derive(Protocol)]
        enum Subcommand {}

        let running = gix::open(LIVE_REPO_PATH)?.head_commit()?.id;
        let user_dirs = UserDirs::new().ok_or(Error::UserDirs)?;
        let next_path = user_dirs.home_dir().join("bin").join("midos-house-next");
        let mw_next_path = user_dirs.home_dir().join("bin").join("ootrmwd-next");
        let mut built_commit = match Command::new(&next_path).arg("--version").stdout(Stdio::piped()).check("midos-house-next --version").await {
            Ok(process::Output { stdout, .. }) => regex_captures!(r"\(([0-9a-z]{40})\)", &String::from_utf8(stdout)?).ok_or(Error::NextVersion)?.1.parse()?,
            Err(wheel::Error::Io { inner, .. }) if inner.kind() == io::ErrorKind::NotFound => running,
            Err(e) => return Err(e.into()),
        };
        let (webhook_tx, mut webhook_rx) = mpsc::channel(256);
        let this = Self {
            build_repo_lock: Arc::default(),
            self_repo_lock: Arc::default(),
            status: Arc::new(RwLock::new(Status {
                watch: watch::Sender::default(),
                running,
                future: {
                    let mut future = Vec::default();
                    Command::new("git").arg("fetch").current_dir(BUILD_REPO_PATH).check("git fetch").await?; //TODO use GitHub API or gix (how?)
                    let repo = gix::open(BUILD_REPO_PATH)?;
                    let new_head = repo.find_reference("origin/main")?.peel_to_commit()?.id;
                    if new_head != running {
                        let mut iter_commit = repo.find_commit(new_head)?;
                        future = vec![(new_head, iter_commit.message()?.summary().to_string())];
                        loop {
                            let Ok(parent) = iter_commit.parent_ids().exactly_one() else {
                                // initial commit or merge commit; skip parents for simplicity's sake
                                break
                            };
                            if parent == running { break }
                            iter_commit = parent.object()?.peel_to_commit()?;
                            future.push((parent.detach(), iter_commit.message()?.summary().to_string()));
                        }
                    }
                    let built_idx = future.iter().position(|(commit_hash, _)| *commit_hash == built_commit);
                    future.into_iter().enumerate().rev().map(|(idx, (commit_hash, commit_msg))| (commit_hash, commit_msg, if let Some(built_idx) = built_idx {
                        match idx.cmp(&built_idx) {
                            Less => CommitStatus::Pending,
                            Equal => CommitStatus::PrepareStopInit,
                            Greater => CommitStatus::Bundled,
                        }
                    } else {
                        CommitStatus::Pending
                    })).collect()
                },
                self_future: {
                    let mut self_future = Vec::default();
                    Command::new("git").arg("fetch").current_dir(SELF_REPO_PATH).check("git fetch").await?; //TODO use GitHub API or gix (how?)
                    let repo = gix::open(SELF_REPO_PATH)?;
                    let new_head = repo.find_reference("origin/main")?.peel_to_commit()?.id;
                    if new_head != GIT_COMMIT_HASH {
                        let mut iter_commit = repo.find_commit(new_head)?;
                        self_future = vec![(new_head, iter_commit.message()?.summary().to_string())];
                        loop {
                            let Ok(parent) = iter_commit.parent_ids().exactly_one() else {
                                // initial commit or merge commit; skip parents for simplicity's sake
                                break
                            };
                            if parent == GIT_COMMIT_HASH { break }
                            iter_commit = parent.object()?.peel_to_commit()?;
                            self_future.push((parent.detach(), iter_commit.message()?.summary().to_string()));
                        }
                    }
                    self_future.into_iter().rev().map(|(commit_hash, commit_msg)| (commit_hash, commit_msg, SelfCommitStatus::Pending)).collect()
                },
            })),
            webhook: webhook_tx,
        };
        let mut build_task = this.build_task(&user_dirs, &next_path).await;
        let mut mw_build_task = None;
        let mut self_build_task = this.self_build_task(&user_dirs).await;
        let mut needs_rebuild = false;
        let mut needs_mw_rebuild = VecDeque::default();
        let mut needs_self_rebuild = false;
        let (mut prepare_stop_child, mut prepare_stop_read) = if built_commit == running {
            (None, future::pending().boxed())
        } else {
            let mut child = Command::new(BIN_PATH).arg("prepare-stop").arg("--async-proto").stdout(Stdio::piped()).spawn().at_command("midos-house prepare-stop")?;
            let prepare_stop_read = PrepareStopUpdate::read_owned(child.stdout.take().expect("stdout was piped"));
            (Some(child), prepare_stop_read)
        };
        let mut needs_self_restart = false;
        #[cfg(unix)] { fs::remove_file(unix_socket::PATH).await.missing_ok()?; }
        let unix_listener = {
            #[cfg(unix)] { UnixListener::bind(unix_socket::PATH).at(unix_socket::PATH)? }
            #[cfg(not(unix))] { UnixListener }
        };
        let mut unix_streams = FuturesUnordered::default();
        Ok((this.clone(), move |mut shutdown: rocket::Shutdown| async move {
            loop {
                let build_task_or_pending = if let Some(build_task) = &mut build_task {
                    Either::Left(build_task)
                } else {
                    Either::Right(future::pending())
                };
                let mw_build_task_or_pending = if let Some(mw_build_task) = &mut mw_build_task {
                    Either::Left(mw_build_task)
                } else {
                    Either::Right(future::pending())
                };
                let self_build_task_or_pending = if let Some(self_build_task) = &mut self_build_task {
                    Either::Left(self_build_task)
                } else {
                    Either::Right(future::pending())
                };
                select! {
                    () = &mut shutdown => break,
                    () = sleep(Duration::from_secs(24 * 60 * 60)) => {
                        if this.fetch_mh().await? {
                            if build_task.is_some() {
                                needs_rebuild = true;
                            } else {
                                build_task = this.build_task(&user_dirs, &next_path).await;
                            }
                        }
                        if this.fetch_self().await? {
                            if self_build_task.is_some() {
                                needs_self_rebuild = true;
                            } else {
                                self_build_task = this.self_build_task(&user_dirs).await;
                            }
                        }
                    }
                    Some(repo_name) = webhook_rx.recv() => match repo_name {
                        RepoName::MidosHouse => if this.fetch_mh().await? {
                            if build_task.is_some() {
                                println!("supervisor: got webhook for mh, rebuild queued");
                                needs_rebuild = true;
                            } else {
                                println!("supervisor: got webhook for mh, starting build");
                                build_task = this.build_task(&user_dirs, &next_path).await;
                            }
                        } else {
                            println!("supervisor: got webhook for mh but no change");
                        },
                        RepoName::Status => if this.fetch_self().await? {
                            if self_build_task.is_some() {
                                needs_self_rebuild = true;
                            } else {
                                self_build_task = this.self_build_task(&user_dirs).await;
                            }
                        },
                    },
                    res = build_task_or_pending => {
                        built_commit = res??;
                        println!("supervisor: build finished");
                        lock!(@write status = this.status; {
                            let _ = status.watch.send(());
                            if let Some(built_idx) = status.future.iter().position(|(commit_hash, _, _)| *commit_hash == built_commit) {
                                let prepare_stop_status = status.future.iter()
                                    .find(|(_, _, status)| status.is_prepare_stop())
                                    .map(|(_, _, status)| status.clone())
                                    .unwrap_or(CommitStatus::PrepareStopInit);
                                for (idx, (_, _, status)) in status.future.iter_mut().enumerate() {
                                    *status = match idx.cmp(&built_idx) {
                                        Less => CommitStatus::Bundled,
                                        Equal => prepare_stop_status.clone(),
                                        Greater => CommitStatus::Pending,
                                    };
                                }
                            }
                        });
                        build_task = if needs_rebuild {
                            println!("supervisor: needs rebuild");
                            needs_rebuild = false;
                            this.build_task(&user_dirs, &next_path).await
                        } else {
                            if needs_self_restart && mw_build_task.is_none() {
                                println!("supervisor: notifying rocket to shut down");
                                shutdown.notify();
                                println!("supervisor: exiting for self-restart");
                                break
                            } else {
                                println!("supervisor: no rebuild or restart needed");
                            }
                            None
                        };
                        if prepare_stop_child.is_none() {
                            let mut child = Command::new(BIN_PATH).arg("prepare-stop").arg("--async-proto").stdout(Stdio::piped()).spawn().at_command("midos-house prepare-stop")?;
                            prepare_stop_read = PrepareStopUpdate::read_owned(child.stdout.take().expect("stdout was piped"));
                            prepare_stop_child = Some(child);
                        }
                    }
                    res = mw_build_task_or_pending => {
                        let mut sock = res??;
                        0u8.write(&mut sock).await?;
                        unix_streams.push(Subcommand::read_owned(sock));
                        mw_build_task = if let Some(sock) = needs_mw_rebuild.pop_front() {
                            Some(this.mw_build_task(&user_dirs, &mw_next_path, sock).await)
                        } else {
                            if needs_self_restart && build_task.is_none() {
                                println!("supervisor: notifying rocket to shut down");
                                shutdown.notify();
                                println!("supervisor: exiting for self-restart");
                                break
                            }
                            None
                        };
                    }
                    res = self_build_task_or_pending => {
                        let built_commit = res??;
                        lock!(@write status = this.status; {
                            let _ = status.watch.send(());
                            if let Some(built_idx) = status.self_future.iter().position(|(commit_hash, _, _)| *commit_hash == built_commit) {
                                for (idx, (_, _, status)) in status.self_future.iter_mut().enumerate() {
                                    *status = match idx.cmp(&built_idx) {
                                        Less => SelfCommitStatus::Bundled,
                                        Equal => SelfCommitStatus::WaitRestart,
                                        Greater => SelfCommitStatus::Pending,
                                    };
                                }
                            }
                        });
                        self_build_task = if needs_self_rebuild {
                            needs_self_rebuild = false;
                            this.self_build_task(&user_dirs).await
                        } else {
                            None
                        };
                        if build_task.is_some() || mw_build_task.is_some() {
                            needs_self_restart = true;
                        } else {
                            println!("supervisor: notifying rocket to shut down");
                            shutdown.notify();
                            println!("supervisor: exiting for self-restart");
                            break
                        }
                    }
                    res = &mut prepare_stop_read => match res {
                        Ok((stdout, update)) => {
                            prepare_stop_read = PrepareStopUpdate::read_owned(stdout);
                            lock!(@write status = this.status; if let Some(idx) = status.future.iter().position(|(_, _, status)| status.is_prepare_stop()) {
                                let _ = status.watch.send(());
                                match update {
                                    PrepareStopUpdate::AcquiringMutex => status.future[idx].2 = CommitStatus::PrepareStopAcquiringMutex,
                                    PrepareStopUpdate::WaitingForRooms(mut rooms) => {
                                        rooms.retain(|room| room.is_public());
                                        status.future[idx].2 = CommitStatus::WaitingForRooms { rooms };
                                    }
                                    PrepareStopUpdate::RoomOpened(room) => if room.is_public() {
                                        if let CommitStatus::WaitingForRooms { rooms } = &mut status.future[idx].2 {
                                            rooms.insert(room);
                                        }
                                    },
                                    PrepareStopUpdate::RoomClosed(room) => if room.is_public() {
                                        if let CommitStatus::WaitingForRooms { rooms } = &mut status.future[idx].2 {
                                            rooms.remove(&room);
                                        }
                                    },
                                }
                            });
                        }
                        Err(ReadError { kind: ReadErrorKind::EndOfStream, .. }) => {
                            prepare_stop_read = future::pending().boxed();
                        }
                        Err(ReadError { kind: ReadErrorKind::Io(e), .. }) if e.kind() == io::ErrorKind::UnexpectedEof => {
                            prepare_stop_read = future::pending().boxed();
                        }
                        Err(e) => return Err(e.into()),
                    },
                    res = if let Some(child) = &mut prepare_stop_child { Either::Left(child.wait()) } else { Either::Right(future::pending()) } => {
                        let _ = res.at_command("midos-house prepare-stop")?; // intentionally not checking exit status as prepare-stop crashing is also a good reason to restart Mido's House
                        prepare_stop_child = None;
                        prepare_stop_read = future::pending().boxed();
                        lock!(@write status = this.status; if let Some(idx) = status.future.iter().position(|(_, _, status)| status.is_prepare_stop()) {
                            let _ = status.watch.send(());
                            status.future[idx].2 = CommitStatus::Deploy;
                        });
                        println!("supervisor: stopping old version");
                        Command::new("sudo").arg("/usr/bin/systemctl").arg("stop").arg("midos-house").check("systemctl stop").await?;
                        println!("supervisor: pulling git repo");
                        Command::new("git").arg("fetch").current_dir(LIVE_REPO_PATH).check("git fetch").await?;
                        Command::new("git").arg("reset").arg("--hard").arg(built_commit.to_string()).current_dir(LIVE_REPO_PATH).check("git reset").await?;
                        println!("supervisor: replacing binary");
                        fs::rename(&next_path, BIN_PATH).await?;
                        println!("supervisor: starting new version");
                        Command::new("sudo").arg("/usr/bin/systemctl").arg("start").arg("midos-house").check("systemctl start").await?;
                        println!("supervisor: update completed");
                        lock!(@write status = this.status; {
                            let _ = status.watch.send(());
                            status.running = built_commit;
                            if let Some(idx) = status.future.iter().position(|(iter_commit, _, _)| *iter_commit == built_commit) {
                                status.future.drain(..=idx);
                            }
                        });
                    }
                    res = unix_listener.accept() => {
                        let (sock, _) = res.at_unknown()?;
                        unix_streams.push(Subcommand::read_owned(sock));
                    }
                    Some(res) = unix_streams.next() => match res {
                        #[allow(unused)] Ok((sock, subcommand)) => {
                            match subcommand {
                                #[cfg(unix)] Subcommand::BuildMw => {
                                    if mw_build_task.is_some() {
                                        needs_mw_rebuild.push_back(sock);
                                    } else {
                                        mw_build_task = Some(this.mw_build_task(&user_dirs, &mw_next_path, sock).await);
                                    }
                                    continue
                                }
                            }
                            unix_streams.push(Subcommand::read_owned(sock));
                        }
                        Err(ReadError { kind: ReadErrorKind::Io(e), .. }) if e.kind() == io::ErrorKind::UnexpectedEof => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Ok(())
        }.boxed()))
    }

    pub(crate) async fn handle_webhook(&self, repo_name: RepoName) {
        self.webhook.send(repo_name).await.allow_unreceived();
    }

    pub(crate) async fn status(&self) -> tokio::sync::RwLockReadGuard<'_, Status> {
        self.status.inner.read().await
    }

    async fn fetch_mh(&self) -> Result<bool, Error> {
        Ok(lock!(build_repo_lock = self.build_repo_lock; {
            Command::new("git").arg("fetch").current_dir(BUILD_REPO_PATH).check("git fetch").await?; //TODO use GitHub API or gix (how?)
            let repo = gix::open(BUILD_REPO_PATH)?;
            let new_head = repo.find_reference("origin/main")?.peel_to_commit()?.id;
            lock!(@write status = self.status; {
                let _ = status.watch.send(());
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
                    true
                } else {
                    false
                }
            })
        }))
    }

    async fn fetch_self(&self) -> Result<bool, Error> {
        Ok(lock!(self_repo_lock = self.self_repo_lock; {
            Command::new("git").arg("fetch").current_dir(SELF_REPO_PATH).check("git fetch").await?; //TODO use GitHub API or gix (how?)
            let repo = gix::open(SELF_REPO_PATH)?;
            let new_head = repo.find_reference("origin/main")?.peel_to_commit()?.id;
            lock!(@write status = self.status; {
                let _ = status.watch.send(());
                let status_latest = status.self_future.last().map_or(GIT_COMMIT_HASH, |(latest, _, _)| *latest);
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
                    status.self_future.extend(to_add.into_iter().rev().map(|(commit_hash, commit_msg)| (commit_hash, commit_msg, SelfCommitStatus::Pending)));
                    true
                } else {
                    false
                }
            })
        }))
    }

    async fn build_task(&self, user_dirs: &UserDirs, next_path: &Path) -> Option<tokio::task::JoinHandle<Result<gix::ObjectId, Error>>> {
        lock!(@write status = self.status; {
            let _ = status.watch.send(());
            for (_, _, status) in &mut status.future {
                if let CommitStatus::Pending = status {
                    *status = CommitStatus::Bundled;
                }
            }
            if let Some((new_head, _, status @ CommitStatus::Bundled)) = status.future.last_mut() {
                *status = CommitStatus::Build;
                let new_head = *new_head;
                let user_dirs = user_dirs.clone();
                let next_path = next_path.to_owned();
                Some(tokio::spawn(async move {
                    Command::new("git").arg("reset").arg("--hard").arg(new_head.to_string()).current_dir(BUILD_REPO_PATH).check("git reset").await?;
                    if !which("rustup").is_ok_and(|rustup_path| rustup_path.starts_with("/nix/store")) { // skip self-update if rustup is managed (nix is assumed to be updated automatically)
                        println!("supervisor: updating rustup");
                        let lock = DirLock::new(rust_lock_dir()).await?;
                        let mut rustup_cmd = Command::new("rustup");
                        rustup_cmd.arg("self");
                        rustup_cmd.arg("update");
                        rustup_cmd.env("PATH", env::join_paths(iter::once(user_dirs.home_dir().join(".cargo").join("bin")).chain(env::var_os("PATH").map(|path| env::split_paths(&path).collect::<Vec<_>>()).into_iter().flatten()))?);
                        rustup_cmd.kill_on_drop(true);
                        rustup_cmd.create_no_window();
                        rustup_cmd.check("rustup").await?;
                        lock.drop_async().await?;
                    }
                    println!("supervisor: updating Rust");
                    let lock = DirLock::new(rust_lock_dir()).await?;
                    let mut rustup_cmd = Command::new("rustup");
                    rustup_cmd.arg("update");
                    rustup_cmd.arg("stable");
                    rustup_cmd.env("PATH", env::join_paths(iter::once(user_dirs.home_dir().join(".cargo").join("bin")).chain(env::var_os("PATH").map(|path| env::split_paths(&path).collect::<Vec<_>>()).into_iter().flatten()))?);
                    rustup_cmd.kill_on_drop(true);
                    rustup_cmd.create_no_window();
                    rustup_cmd.check("rustup").await?;
                    lock.drop_async().await?;
                    //TODO cargo sweep (limit to once per Rust version)
                    println!("supervisor: building {new_head}");
                    Command::new(user_dirs.home_dir().join(".cargo").join("bin").join("cargo")).arg("build").arg("--release").arg("--target=x86_64-unknown-linux-musl").current_dir(BUILD_REPO_PATH).kill_on_drop(true).check("cargo build").await?;
                    fs::rename(Path::new(BUILD_REPO_PATH).join("target").join("x86_64-unknown-linux-musl").join("release").join("midos-house"), &next_path).await?;
                    Ok(new_head)
                }))
            } else {
                None
            }
        })
    }

    async fn mw_build_task(&self, user_dirs: &UserDirs, next_path: &Path, sock: UnixStream) -> tokio::task::JoinHandle<Result<UnixStream, Error>> {
        let user_dirs = user_dirs.clone();
        let next_path = next_path.to_owned();
        tokio::spawn(async move {
            Command::new("git").arg("fetch").current_dir(MW_BUILD_REPO_PATH).check("git fetch").await?;
            Command::new("git").arg("reset").arg("--hard").arg("origin/main").current_dir(MW_BUILD_REPO_PATH).check("git reset").await?;
            if !which("rustup").is_ok_and(|rustup_path| rustup_path.starts_with("/nix/store")) { // skip self-update if rustup is managed (nix is assumed to be updated automatically)
                println!("supervisor: updating rustup");
                let lock = DirLock::new(rust_lock_dir()).await?;
                let mut rustup_cmd = Command::new("rustup");
                rustup_cmd.arg("self");
                rustup_cmd.arg("update");
                rustup_cmd.env("PATH", env::join_paths(iter::once(user_dirs.home_dir().join(".cargo").join("bin")).chain(env::var_os("PATH").map(|path| env::split_paths(&path).collect::<Vec<_>>()).into_iter().flatten()))?);
                rustup_cmd.kill_on_drop(true);
                rustup_cmd.create_no_window();
                rustup_cmd.check("rustup").await?;
                lock.drop_async().await?;
            }
            println!("supervisor: updating Rust");
            let lock = DirLock::new(rust_lock_dir()).await?;
            let mut rustup_cmd = Command::new("rustup");
            rustup_cmd.arg("update");
            rustup_cmd.arg("stable");
            rustup_cmd.env("PATH", env::join_paths(iter::once(user_dirs.home_dir().join(".cargo").join("bin")).chain(env::var_os("PATH").map(|path| env::split_paths(&path).collect::<Vec<_>>()).into_iter().flatten()))?);
            rustup_cmd.kill_on_drop(true);
            rustup_cmd.create_no_window();
            rustup_cmd.check("rustup").await?;
            lock.drop_async().await?;
            //TODO cargo sweep (limit to once per Rust version)
            println!("supervisor: building mw");
            Command::new(user_dirs.home_dir().join(".cargo").join("bin").join("cargo")).arg("build").arg("--release").arg("--package=ootrmwd").arg("--features=require-user-agent-salt").current_dir(MW_BUILD_REPO_PATH).kill_on_drop(true).check("cargo build").await?;
            fs::rename(Path::new(MW_BUILD_REPO_PATH).join("target").join("release").join("ootrmwd"), &next_path).await?;
            Ok(sock)
        })
    }

    async fn self_build_task(&self, user_dirs: &UserDirs) -> Option<tokio::task::JoinHandle<Result<gix::ObjectId, Error>>> {
        lock!(@write status = self.status; {
            let _ = status.watch.send(());
            for (_, _, status) in &mut status.self_future {
                if let SelfCommitStatus::Pending = status {
                    *status = SelfCommitStatus::Bundled;
                }
            }
            if let Some((new_head, _, status @ SelfCommitStatus::Bundled)) = status.self_future.last_mut() {
                *status = SelfCommitStatus::Build;
                let new_head = *new_head;
                let user_dirs = user_dirs.clone();
                Some(tokio::spawn(async move {
                    Command::new("git").arg("reset").arg("--hard").arg(new_head.to_string()).current_dir(SELF_REPO_PATH).check("git reset").await?;
                    if !which("rustup").is_ok_and(|rustup_path| rustup_path.starts_with("/nix/store")) { // skip self-update if rustup is managed (nix is assumed to be updated automatically)
                        println!("supervisor: updating rustup");
                        let lock = DirLock::new(rust_lock_dir()).await?;
                        let mut rustup_cmd = Command::new("rustup");
                        rustup_cmd.arg("self");
                        rustup_cmd.arg("update");
                        rustup_cmd.env("PATH", env::join_paths(iter::once(user_dirs.home_dir().join(".cargo").join("bin")).chain(env::var_os("PATH").map(|path| env::split_paths(&path).collect::<Vec<_>>()).into_iter().flatten()))?);
                        rustup_cmd.kill_on_drop(true);
                        rustup_cmd.create_no_window();
                        rustup_cmd.check("rustup").await?;
                        lock.drop_async().await?;
                    }
                    println!("supervisor: updating Rust");
                    let lock = DirLock::new(rust_lock_dir()).await?;
                    let mut rustup_cmd = Command::new("rustup");
                    rustup_cmd.arg("update");
                    rustup_cmd.arg("stable");
                    rustup_cmd.env("PATH", env::join_paths(iter::once(user_dirs.home_dir().join(".cargo").join("bin")).chain(env::var_os("PATH").map(|path| env::split_paths(&path).collect::<Vec<_>>()).into_iter().flatten()))?);
                    rustup_cmd.kill_on_drop(true);
                    rustup_cmd.create_no_window();
                    rustup_cmd.check("rustup").await?;
                    lock.drop_async().await?;
                    //TODO cargo sweep (limit to once per Rust version)
                    println!("supervisor: building self {new_head}");
                    Command::new(user_dirs.home_dir().join(".cargo").join("bin").join("cargo")).arg("install-update").arg("--all").arg("--git").check("cargo install-update").await?;
                    Ok(new_head)
                }))
            } else {
                None
            }
        })
    }
}
