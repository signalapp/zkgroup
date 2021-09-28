FROM debian:stretch

COPY docker/ docker/
COPY docker/apt.conf docker/sources.list /etc/apt/

RUN    dpkg --add-architecture i386

RUN    apt-get update \
    && apt-get install -y --no-install-recommends \
               software-properties-common

RUN    apt-get update \
    && apt-get install -y --no-install-recommends \
               apt-transport-https \
               build-essential \
               git \
               curl \
               wget \
               gpg-agent \
               openssh-client \
               unzip

# Install pinned dependencies
RUN    apt-get install -y $(cat docker/dependencies.txt)
RUN    docker/print-versions.sh docker/dependencies.txt

RUN    rm -rf /var/lib/apt/lists/* && \
       apt-get autoremove -y && \
       apt-get clean

ARG UID
ARG GID

# Create a user to map the host user to.
RUN    groupadd -o -g "${GID}" zkgroup \
    && useradd -m -o -u "${UID}" -g "${GID}" -s /bin/bash zkgroup

USER zkgroup
ENV HOME /home/zkgroup
ENV USER zkgroup
ENV SHELL /bin/bash

WORKDIR /home/zkgroup

# Rust setup...
COPY rust-toolchain.toml rust-toolchain.toml
ARG RUSTUP_SHA256=3dc5ef50861ee18657f9db2eeb7392f9c2a6c95c90ab41e45ab4ca71476b4338
ARG CARGO_NDK_VERSION=1.0.0
ENV PATH="/home/zkgroup/.cargo/bin:${PATH}"

RUN    curl -f https://static.rust-lang.org/rustup/archive/1.24.3/x86_64-unknown-linux-gnu/rustup-init -o /tmp/rustup-init \
    && echo "${RUSTUP_SHA256} /tmp/rustup-init" | sha256sum -c - \
    && chmod a+x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile default --default-toolchain nightly-2021-09-19 \
    && rm -rf /tmp/rustup-init \
    && rustup component add rust-src \
    && rustup target add aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-apple-darwin x86_64-apple-ios x86_64-linux-android x86_64-unknown-linux-gnu \
    && cargo install --version ${CARGO_NDK_VERSION} cargo-ndk

# Android SDK setup...
ARG ANDROID_SDK_FILENAME=commandlinetools-linux-6200805_latest.zip
ARG ANDROID_SDK_SHA=f10f9d5bca53cc27e2d210be2cbc7c0f1ee906ad9b868748d74d62e10f2c8275
ARG ANDROID_API_LEVELS=android-28
ARG ANDROID_BUILD_TOOLS_VERSION=28.0.3
ARG NDK_VERSION=21.0.6113669
ENV ANDROID_HOME /home/zkgroup/android-sdk
ENV NDK_HOME ${ANDROID_HOME}/ndk/${NDK_VERSION}
ENV PATH ${PATH}:${ANDROID_HOME}/tools:${ANDROID_HOME}/platform-tools

RUN    wget -q https://dl.google.com/android/repository/${ANDROID_SDK_FILENAME} \
    && echo "${ANDROID_SDK_SHA} ${ANDROID_SDK_FILENAME}" | sha256sum -c - \
    && unzip -q ${ANDROID_SDK_FILENAME} -d android-sdk \
    && rm -rf ${ANDROID_SDK_FILENAME} \
    && echo y | ./android-sdk/tools/bin/sdkmanager --sdk_root=${ANDROID_HOME} "platforms;${ANDROID_API_LEVELS}" \
    && ./android-sdk/tools/bin/sdkmanager --sdk_root=${ANDROID_HOME} "build-tools;${ANDROID_BUILD_TOOLS_VERSION}" \
    && ./android-sdk/tools/bin/sdkmanager --sdk_root=${ANDROID_HOME} "platform-tools" \
    && ./android-sdk/tools/bin/sdkmanager --sdk_root=${ANDROID_HOME} "ndk;${NDK_VERSION}"

# Pre-download Gradle.
COPY   gradle gradle
COPY   gradlew .
RUN    ./gradlew --version

# Convert ssh to https for git dependency access without a key.
RUN    git config --global url."https://github".insteadOf ssh://git@github

CMD [ "/bin/bash" ]
