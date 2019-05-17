FROM rustlang/rust:nightly
ENV RUST_LOG warning
RUN ["cargo", "test", "--all-features", "--", "--nocapture"]
