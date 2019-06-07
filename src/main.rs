#![deny(unused_must_use)]

#[macro_use]
extern crate log;

use std::io::Error as IoError;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap;
use futures::Stream;
use futures::future::Future;
use hyper::Server;

use rusty_kms::misc::get_password_from_tty;
use rusty_kms::key_store::{Store, PortableStore};

#[cfg(not(feature = "authorisation"))]
use rusty_kms::authorisation::open::OpenAuthorisationProvider;
#[cfg(feature = "authorisation")]
use rusty_kms::authorisation::access_tokens::AccessToken;
#[cfg(feature = "authorisation")]
use rusty_kms::authorisation::headerv4::HeaderV4AuthorisationProvider;

mod server;

fn main() {
    env_logger::from_env(env_logger::Env::default().default_filter_or("rusty_kms=info")).init();
    if std::mem::size_of::<usize>() != 8 {
        error!("Only supports 64bit systems");
        std::process::exit(1);
    }

    let app = clap::App::new("Rusty KMS").version(env!("CARGO_PKG_VERSION"))
        .arg(clap::Arg::with_name("address")
            .help("Address and port to listen on")
            .default_value("127.0.0.1:6767"))
        .arg(clap::Arg::with_name("data_path").long("data")
            .help("Key store directory")
            .takes_value(true))
        .arg(clap::Arg::with_name("import_path").long("import")
            .help("File to import keys from")
            .takes_value(true));
    let args = add_auth_args(app).get_matches();
    let address: SocketAddr = args.value_of("address")
        .and_then(|address| match address.parse() {
            Ok(address) => Some(address),
            _ => {
                error!("Unable to parse address");
                std::process::exit(1);
            },
        }).unwrap();
    let mut key_store = match args.value_of("data_path") {
        Some(path) => Store::with_persistence(path, get_password_from_tty)
            .unwrap_or_else(|e| {
                error!("Cannot open key store: {}", e);
                std::process::exit(1);
            }),
        None => Store::new(),
    };
    let portable_store = args.value_of("import_path")
        .map(|import_path| PortableStore::load_from(import_path).unwrap_or_else(|e| {
            error!("Cannot read keys: {}", e);
            std::process::exit(1);
        }));
    if let Some(portable_store) = portable_store {
        let (key_count, alias_count) = key_store.add_from_portable_store(portable_store)
            .unwrap_or_else(|e| {
                error!("Cannot import keys: {}", e);
                std::process::exit(1);
            });
        info!("Imported {} keys and {} aliases", key_count, alias_count);
    }

    let key_store = Arc::new(Mutex::new(key_store));
    let key_store_ref = Arc::downgrade(&key_store);

    let (tx, rx) = futures::sync::oneshot::channel::<()>();
    let shutdown_signal = Arc::new(Mutex::new(Some(tx)));

    let auth_provider = load_auth_provider(&args).unwrap_or_else(|e| {
        error!("Cannot create auth provider: {}", e);
        std::process::exit(1);
    });
    let service = server::KMSNewService::new(Arc::clone(&key_store), auth_provider);
    let server = Server::bind(&address)
        .serve(service)
        .with_graceful_shutdown(rx)
        .map_err(|e| error!("Server error: {}", e));

    info!("Starting Rusty KMS {} server on {}", env!("CARGO_PKG_VERSION"), address);
    let mut runtime = tokio::runtime::Runtime::new().expect("cannot create runtime");

    // signal handler to trigger graceful server shutdown
    runtime.spawn(
        tokio_signal::ctrl_c()
            .flatten_stream()
            .map_err(|e| {
                error!("Signal handling error: {}", e);
            })
            .for_each(move |_| {
                start_shutdown(&shutdown_signal);
                Ok(())
            })
    );

    // clean up key store periodically
    runtime.spawn(
        tokio::timer::Interval::new_interval(Duration::new(60 * 10, 0))
            .map_err(|e| {
                error!("Timer error: {}", e);
            })
            .for_each(move |_| {
                key_store_ref.upgrade().map(|key_store| {
                    let mut key_store = key_store.lock().expect("cannot lock key store");
                    key_store.update_if_necessary();
                    drop(key_store);
                }).ok_or(())
            })
    );

    runtime.block_on(server).expect("error waiting for server to complete");
}

#[cfg(not(feature = "authorisation"))]
fn add_auth_args<'a, 'b>(app: clap::App<'a, 'b>) -> clap::App<'a, 'b> {
    app
        .arg(clap::Arg::with_name("region").long("region")
            .help("Default AWS region for all key interactions")
            .default_value("eu-west-2")
            .takes_value(true))
        .arg(clap::Arg::with_name("account_id").long("account-id")
            .help("Default AWS account for all key interactions")
            .default_value("0000000")
            .takes_value(true))
}

#[cfg(not(feature = "authorisation"))]
fn load_auth_provider(args: &clap::ArgMatches) -> Result<OpenAuthorisationProvider, IoError> {
    let region = args.value_of("region").unwrap();
    let account_id = args.value_of("account_id").unwrap();
    Ok(OpenAuthorisationProvider::new(region, account_id))
}

#[cfg(feature = "authorisation")]
fn add_auth_args<'a, 'b>(app: clap::App<'a, 'b>) -> clap::App<'a, 'b> {
    app
        .arg(clap::Arg::with_name("access_tokens").long("access-tokens")
            .help("Path to access token JSON")
            .required(true)
            .takes_value(true))
}

#[cfg(feature = "authorisation")]
fn load_auth_provider(args: &clap::ArgMatches) -> Result<HeaderV4AuthorisationProvider, IoError> {
    let access_tokens = args.value_of("access_tokens").unwrap();
    let access_tokens = AccessToken::load_from(access_tokens)?;
    Ok(HeaderV4AuthorisationProvider::new(access_tokens))
}

fn start_shutdown(shutdown_signal: &Arc<Mutex<Option<futures::sync::oneshot::Sender<()>>>>) {
    let mut shutdown_signal = shutdown_signal.lock().expect("cannot obtain shutdown signal");
    match shutdown_signal.take() {
        Some(shutdown_signal) => {
            warn!("Shutting down");
            shutdown_signal.send(()).expect("cannot send shutdown signal");
        },
        None => error!("Shutdown signal already used"),
    }
}
