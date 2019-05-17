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
cargo run --features authorisation -- --access-tokens [path to token list] [options]
```

…where the token list is a JSON file with a list of access tokens. See `./examples/auth.json`.

Note that without the authorisation feature, all keys are handled with a single account ID and region.

By default, keys are volatile and data is kept in memory only while the server is running.
If you need key persistence, they can be kept in a password protected key store:

```bash
# replace [options] above with
--data [key store path] [options]
```

You can inspect key store contents with:

```bash
cargo run --example browser -- --data [key store path] [options]
```

The server can also run in a Docker container (currently without AWS V4 header-based signatures enabled):

```bash
docker build --tag rusty-kms --force-rm .

docker run -it --rm --publish 6767:6767 --name rusty-kms \
    rusty-kms [options]
# or with persistence:
docker run -it --rm --publish 6767:6767 --name rusty-kms \
    --mount type=bind,source=[local path],target=/var/run/rusty_kms \
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
aws --endpoint-url http://127.0.0.1:6767/ kms list-keys
```

With python boto3 library:

```python
import boto3
client = boto3.client('kms', endpoint_url='http://127.0.0.1:6767/')
print(client.list_keys()['Keys'])
```

Test
----

```bash
cargo test --all-features -- --nocapture
cargo clippy --all-features
```

To-do
-----

* Error responses and status codes are likely messed up with respect to AWS
* Key seeding: allow importing like local-kms
* Better mock authentication and accounts
* Key policies / grants
* Tidy module structure, visibility and maybe hide key handling internals better
* Maybe use toml or yaml as serialisation format
* Server methods are very repetitive, but cannot factor out deserialisation because values are borrowed..?
    * Make data type own contents?
    * Will async/await constructs help once part of the language?
* Test coverage is very low
* Use `rusoto` types and/or credential loading?