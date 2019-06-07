Rusty KMS
=========

Mock implementation of [AWS KMS](https://docs.aws.amazon.com/kms/latest/APIReference/Welcome.html) service for testing purposes.

Inspired by [local-kms](https://github.com/nsmithuk/local-kms).

**NB: This should not be used for genuine cryptographic purposes.**

Also note that this is probably written in terrible rust!

Developed using rust 1.36-nightly.

Run server
----------

By compiling and running directly:

```bash
cargo run -- [options]
```

Or with authorisation enabled (using AWS V4 header-based signatures):

```bash
cargo run --features authorisation -- --access-tokens [token list path] [options]
```

…where the token list is a JSON file with a list of access tokens. See `./examples/access-tokens.json`.

Note that without the authorisation feature, all keys are handled with a single account ID and region.

By default, keys are volatile and data is kept in memory only while the server is running.
If you need key persistence, they can be kept in a password protected key store:

```bash
# replace [options] above with
--data [key store directory] [options]
```

When the server is started, keys can automatically be imported into the key store:

```bash
# replace [options] above with
--import [key list path] [options]
```

…where the key list is a JSON file with a list of keys and aliases. See `./examples/keys.json`.

You can inspect key store contents with:

```bash
cargo run --example browser -- [key store directory] [options]
```

The server can also run in a Docker container (currently without AWS V4 header-based signatures enabled):

```bash
docker build --tag rusty-kms --force-rm .

docker run -it --rm --publish 6767:6767 --name rusty-kms \
    rusty-kms [options]
# or with persistence:
docker run -it --rm --publish 6767:6767 --name rusty-kms \
    --mount type=bind,source=[local directory],target=/var/run/rusty_kms \
    rusty-kms 0.0.0.0:6767 --data /var/run/rusty_kms
```


Use server
----------

With rust:

```bash
cargo run --example demo -- [options]
```

With AWS CLI tools:

```bash
pip install -r examples/demo-requirements.txt 
aws --endpoint-url http://127.0.0.1:6767/ kms list-keys
```

With python boto3 library:

```bash
pip install -r examples/demo-requirements.txt 
python examples/demo.py
```

Test
----

```bash
cargo test --all-features -- --nocapture
cargo bench --all-features -- --nocapture
cargo clippy --all-features
```

To-do
-----

* Check requests:
    * Key lookup by id does not allow cross-account usage
    * Which actions allow aliases
    * Action vs key state
    * Tagging: can remove non-existant tag?
* Error responses and status codes often do not match AWS responses
* Better mock authentication and accounts
* Key policies / grants
* Mock custom key stores
* Improve module structure so that server can only access key and store methods with authorisation
* Maybe use more resilient pagination using mutation flag in marker
* Maybe use toml or yaml as serialisation format
* Server methods are very repetitive, but cannot factor out deserialisation because values are borrowed..?
    * Make data type own contents or use Cows?
    * Will async/await constructs help once part of the language?
* Test coverage is very low
    * Test integrity checks
* Use `rusoto` types and/or credential loading?
