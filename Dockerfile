FROM rustlang/rust:nightly as BASE_BUILD
WORKDIR /var/run/rusty_kms
COPY . .
RUN cargo install --release --path .
RUN strip /usr/local/cargo/bin/rusty-kms

FROM buildpack-deps:stretch
COPY --from=BASE_BUILD /usr/local/cargo/bin/rusty-kms /usr/local/bin/rusty-kms
RUN mkdir -p /var/run/rusty_kms && chmod a+rwx /var/run/rusty_kms
VOLUME /var/run/rusty_kms
USER www-data
EXPOSE 6767
ENTRYPOINT ["rusty-kms"]
CMD ["0.0.0.0:6767"]
