FROM ubuntu:latest

WORKDIR /app
RUN apt-get update && apt-get install curl -y && curl https://sh.rustup.rs -sSf | bash -s -- -y

COPY ./src ./src
COPY ./Cargo.toml .
COPY ./Cargo.lock .

RUN /root/.cargo/bin/cargo build --release

RUN cp ./target/release/example .
RUN rm -rf ./src
RUN rm  Cargo.toml
RUN rm  Cargo.lock

ENTRYPOINT [ "./example" ]
