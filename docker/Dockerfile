FROM ubuntu:20.04

ENV TZ=Europe/Samara
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app
RUN apt-get update && apt-get install curl -y && curl https://sh.rustup.rs -sSf | bash -s -- -y\
&& apt-get install build-essential -y && apt-get install libclang-dev -y && apt-get install pkg-config -y && apt-get install ffmpeg libavcodec-dev libavformat-dev libavdevice-dev -y

COPY ./src ./src
COPY ./Cargo.toml .
COPY ./Cargo.lock .

RUN /root/.cargo/bin/cargo build --release

RUN cp ./target/release/example .
RUN rm -rf ./src
RUN rm  Cargo.toml
RUN rm  Cargo.lock

ENTRYPOINT [ "./example" ]
