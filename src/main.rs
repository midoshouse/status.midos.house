#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use {
    base64::engine::{
        Engine as _,
        general_purpose::STANDARD as BASE64,
    },
    crypto::{
        hmac::Hmac,
        mac::Mac as _,
        sha2::Sha256,
    },
    futures::future::FutureExt as _,
    itermore::IterArrayChunks as _,
    rocket::{
        Rocket,
        State,
        async_trait,
        config::SecretKey,
        data::{
            self,
            Data,
            FromData,
            ToByteUnit as _,
        },
        http::{
            ContentType,
            Status,
        },
        outcome::Outcome,
        request::Request,
        response::content::RawHtml,
        uri,
    },
    rocket_util::{
        Doctype,
        html,
    },
    wheel::traits::IoResultExt as _,
    crate::{
        config::Config,
        supervisor::{
            CommitStatus,
            SelfCommitStatus,
            Supervisor,
        },
    },
};

mod config;
mod supervisor;

include!(concat!(env!("OUT_DIR"), "/version.rs"));

const MW_REPO_PATH: &str = "/opt/git/github.com/midoshouse/ootr-multiworld/main";

#[rocket::get("/")]
async fn index(supervisor: &State<Supervisor>) -> Result<RawHtml<String>, supervisor::RefreshError> {
    supervisor.refresh(true, false).await?;
    let supervisor::Status { ref running, ref future, ref self_future } = *supervisor.status().await;
    Ok(html! {
        : Doctype;
        html {
            head {
                meta(charset = "utf-8");
                title : "Mido's House Status";
                meta(name = "viewport", content = "width=device-width, initial-scale=1, shrink-to-fit=no");
                link(rel = "icon", href = uri!(lens));
                style : RawHtml(include_str!("../assets/common.css"));
            }
            body {
                div(class = "header") {
                    div(class = "logo") {
                        img(class = "chest", src = uri!(chest));
                        img(class = "chest", src = uri!(chest));
                        img(class = "chest", src = uri!(chest));
                        img(class = "chest", src = uri!(chest));
                    }
                    div(class = "header-text") {
                        h1 : "Mido's House ";
                        div(class = "subtitle") : "website, Discord bot, racetime.gg bot";
                    }
                }
                p {
                    : "Currently running: ";
                    code {
                        a(href = format!("https://github.com/midoshouse/midos.house/commit/{running}")) : running.to_hex_with_len(7).to_string();
                    }
                }
                @if future.is_empty() {
                    p : "Mido's House is up to date.";
                } else {
                    p : "Pending updates:";
                    table {
                        thead {
                            tr {
                                th : "Commit";
                                th : "Summary";
                                th : "Status";
                            }
                        }
                        tbody {
                            @for (commit_hash, commit_msg, status) in future {
                                tr {
                                    td {
                                        code {
                                            a(href = format!("https://github.com/midoshouse/midos.house/commit/{commit_hash}")) : commit_hash.to_hex_with_len(7).to_string();
                                        }
                                    }
                                    td : commit_msg;
                                    td {
                                        @match status {
                                            CommitStatus::Pending => : "waiting for other builds to finish";
                                            CommitStatus::Skipped => : "skipped";
                                            CommitStatus::Build => : "building";
                                            CommitStatus::PrepareStop => : "waiting for ongoing races to stop";
                                            CommitStatus::Deploy => : "deploying";
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                div(class = "header") {
                    img(src = uri!(mw_logo));
                    div(class = "header-text") {
                        h1 : "Multiworld";
                        div(class = "subtitle") : "default room server";
                    }
                }
                p {
                    @let mw_commit_hash = gix::open(MW_REPO_PATH)?.head_commit()?.id;
                    : "Currently running: ";
                    code {
                        a(href = format!("https://github.com/midoshouse/ootr-multiworld/commit/{mw_commit_hash}")) : mw_commit_hash.to_hex_with_len(7).to_string();
                    }
                }
                div(class = "header") {
                    img(src = uri!(lens));
                    div(class = "header-text") {
                        h1 : "status.midos.house ";
                        div(class = "subtitle") : "this page";
                    }
                }
                p {
                    : "Currently running: ";
                    code {
                        a(href = format!("https://github.com/midoshouse/status.midos.house/commit/{GIT_COMMIT_HASH}")) : GIT_COMMIT_HASH.to_hex_with_len(7).to_string();
                    }
                }
                @if future.is_empty() {
                    p : "status.midos.house is up to date.";
                } else {
                    p : "Pending updates:";
                    table {
                        thead {
                            tr {
                                th : "Commit";
                                th : "Summary";
                                th : "Status";
                            }
                        }
                        tbody {
                            @for (commit_hash, commit_msg, status) in self_future {
                                tr {
                                    td {
                                        code {
                                            a(href = format!("https://github.com/midoshouse/status.midos.house/commit/{commit_hash}")) : commit_hash.to_hex_with_len(7).to_string();
                                        }
                                    }
                                    td : commit_msg;
                                    td {
                                        @match status {
                                            SelfCommitStatus::Pending => : "waiting for other builds to finish";
                                            SelfCommitStatus::Skipped => : "skipped";
                                            SelfCommitStatus::Build => : "building";
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    })
}

#[rocket::get("/chest.png")]
fn chest() -> (ContentType, &'static [u8]) {
    (ContentType::PNG, include_bytes!("../assets/chest.png"))
}

#[rocket::get("/mw.png")]
fn mw_logo() -> (ContentType, &'static [u8]) {
    (ContentType::PNG, include_bytes!("../assets/mw.png"))
}

#[rocket::get("/lens.svg")]
fn lens() -> (ContentType, &'static [u8]) {
    (ContentType::SVG, include_bytes!("../assets/lens.svg"))
}

macro_rules! guard_try {
    ($res:expr) => {
        match $res {
            Ok(x) => x,
            Err(e) => return Outcome::Error((Status::InternalServerError, e.into())),
        }
    };
}

struct SignedPayload(String);

fn is_valid_signature(signature: &str, body: &str, secret: &str) -> bool {
    let digest = Sha256::new();
    let mut hmac = Hmac::new(digest, secret.as_bytes());
    hmac.input(body.as_bytes());
    let expected_signature = hmac.result();
    let Some((prefix, code)) = signature.split_once('=') else { return false };
    let Ok(code) = code.chars().arrays().map(|[c1, c2]| u8::from_str_radix(&format!("{c1}{c2}"), 16)).collect::<Result<Vec<_>, _>>() else { return false };
    prefix == "sha256" && crypto::util::fixed_time_eq(expected_signature.code(), &code)
}

#[test]
fn test_valid_signature() {
    assert!(is_valid_signature("sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17", "Hello, World!", "It's a Secret to Everybody"))
}

#[test]
fn test_invalid_signature() {
    assert!(!is_valid_signature("sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "Hello, World!", "It's a Secret to Everybody"))
}

#[derive(Debug, thiserror::Error)]
enum PayloadError {
    #[error(transparent)] Wheel(#[from] wheel::Error),
    #[error("config guard forwarded")]
    ConfigForward,
    #[error("value of X-Hub-Signature-256 header is not valid")]
    InvalidSignature,
    #[error("failed to get config")]
    MissingConfig,
    #[error("missing X-Hub-Signature-256 header")]
    MissingSignature,
}

#[async_trait]
impl<'r> FromData<'r> for SignedPayload {
    type Error = PayloadError;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> data::Outcome<'r, Self, Self::Error> {
        if let Some(signature) = req.headers().get_one("X-Hub-Signature-256") {
            let body = guard_try!(data.open(2.mebibytes()).into_string().await.at_unknown());
            match req.guard::<&State<Config>>().await {
                Outcome::Success(config) => if is_valid_signature(signature, &body, &config.github_webhook_secret) {
                    Outcome::Success(Self(body.value))
                } else {
                    Outcome::Error((Status::Unauthorized, PayloadError::InvalidSignature))
                },
                Outcome::Error((status, ())) => Outcome::Error((status, PayloadError::MissingConfig)),
                Outcome::Forward(status) => Outcome::Error((status, PayloadError::ConfigForward)), // can't return Outcome::Forward here since `data` has been moved
            }
        } else {
            Outcome::Error((Status::BadRequest, PayloadError::MissingSignature))
        }
    }
}

#[rocket::post("/github-webhook", data = "<payload>")]
fn github_webhook(supervisor: &State<Supervisor>, payload: SignedPayload) {
    let _ = payload.0; // the data guard has verified that the request came from GitHub and we've only configured the webhook for push events for the midos.house repo for now
    let supervisor = (*supervisor).clone();
    tokio::spawn(async move {
        match supervisor.refresh(false, true).await {
            Ok(()) => {}
            Err(e) => {
                let _ = wheel::night_report("/net/midoshouse/status/error", Some(&format!("refresh failed: {e} ({e:?})"))).await;
            }
        }
    });
}

#[rocket::catch(404)]
fn not_found() -> &'static str { //TODO HTML response
    "Error 404: Not Found"
}

#[rocket::catch(500)]
async fn internal_server_error() -> wheel::Result<&'static str> { //TODO HTML response
    wheel::night_report("/net/midoshouse/status/error", Some("internal server error")).await?;
    Ok("Error 500: Internal Server Error\nSorry, something went wrong. Please notify Fenhl on Discord.")
}

#[rocket::catch(default)]
async fn fallback_catcher(status: Status, _: &Request<'_>) -> wheel::Result<String> { //TODO HTML response
    wheel::night_report("/net/midoshouse/status/error", Some(&format!("responding with unexpected HTTP status code: {} {}", status.code, status.reason_lossy()))).await?;
    Ok(format!("Error {}: {}\nSorry, something went wrong. Please notify Fenhl on Discord.", status.code, status.reason_lossy()))
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)] Base64(#[from] base64::DecodeError),
    #[error(transparent)] Json(#[from] serde_json::Error),
    #[error(transparent)] Rocket(#[from] rocket::Error),
    #[error(transparent)] SupervisorNew(#[from] supervisor::NewError),
    #[error(transparent)] SupervisorRun(#[from] supervisor::RunError),
    #[error(transparent)] Task(#[from] tokio::task::JoinError),
    #[error(transparent)] Wheel(#[from] wheel::Error),
    #[cfg(unix)] #[error(transparent)] Xdg(#[from] xdg::BaseDirectoriesError),
    #[cfg(unix)]
    #[error("missing config file")]
    MissingConfigFile,
}

#[wheel::main(rocket)]
async fn main() -> Result<(), Error> {
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = wheel::night_report_sync("/net/midoshouse/status/error", Some("thread panic"));
        default_panic_hook(info)
    }));
    let config = Config::load().await?;
    let supervisor = Supervisor::new()?;
    let rocket = rocket::custom(rocket::Config {
        secret_key: SecretKey::from(&BASE64.decode(&config.secret_key)?),
        log_level: rocket::config::LogLevel::Critical,
        port: 24824,
        ..rocket::Config::default()
    })
    .mount("/", rocket::routes![
        index,
        chest,
        mw_logo,
        lens,
        github_webhook,
    ])
    .register("/", rocket::catchers![
        not_found,
        internal_server_error,
        fallback_catcher,
    ])
    .manage(config)
    .manage(supervisor.clone())
    .ignite().await?;
    let shutdown = rocket.shutdown();
    let rocket_task = tokio::spawn(rocket.launch()).map(|res| match res {
        Ok(Ok(Rocket { .. })) => Ok(()),
        Ok(Err(e)) => Err(Error::from(e)),
        Err(e) => Err(Error::from(e)),
    });
    let supervisor_task = tokio::spawn(supervisor.run(shutdown)).map(|res| match res {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(Error::from(e)),
        Err(e) => Err(Error::from(e)),
    });
    let ((), ()) = tokio::try_join!(rocket_task, supervisor_task)?;
    Ok(())
}
