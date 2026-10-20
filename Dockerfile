ARG FALCO_VERSION=0.45.1

FROM ubuntu:24.04 AS builder
ARG FALCO_VERSION
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential cmake git ca-certificates curl pkg-config autoconf automake libtool perl unzip \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${FALCO_VERSION} https://github.com/falcosecurity/falco.git /src/falco \
    && echo 'if(EXISTS ${CMAKE_SOURCE_DIR}/userspace/falco-test-engine)\n  add_subdirectory(userspace/falco-test-engine)\nendif()' >> /src/falco/CMakeLists.txt
WORKDIR /src/falco/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release -DMINIMAL_BUILD=ON -DUSE_BUNDLED_DEPS=ON \
      -DBUILD_DRIVER=OFF -DBUILD_FALCO_MODERN_BPF=OFF -DBUILD_FALCO_UNIT_TESTS=OFF \
    && make -j"$(nproc)" falco_engine
# Test assets for engine/test/run.sh: the stock rules and container plugin from the release tarball.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/falco \
    && curl -fsSL "https://download.falco.org/packages/bin/$(uname -m)/falco-${FALCO_VERSION}-$(uname -m).tar.gz" \
       | tar -xz -C /opt/falco --strip-components=1
COPY engine /src/falco/userspace/falco-test-engine
RUN cmake .. && make -j"$(nproc)" falco-test-engine

FROM ubuntu:24.04
ARG FALCO_VERSION
LABEL org.opencontainers.image.source="https://github.com/pogao/falco-test-engine" \
      org.opencontainers.image.description="Test Falco ${FALCO_VERSION} rules against the real Falco engine"
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 python3-yaml ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# The official release supplies the real `falco` binary for the --dry-run startup check, the stock
# rules, and the container plugin that defines container.* and k8s.* fields.
COPY --from=builder /opt/falco/usr/bin/falco /usr/bin/falco
COPY --from=builder /opt/falco/etc/falco /etc/falco
COPY --from=builder /opt/falco/usr/share/falco /usr/share/falco
COPY --from=builder /src/falco/build/userspace/falco-test-engine/falco-test-engine /usr/local/bin/falco-test-engine
COPY ftest /opt/ftest/ftest
RUN printf '#!/bin/sh\nPYTHONPATH=/opt/ftest exec python3 -m ftest "$@"\n' > /usr/local/bin/ftest \
    && chmod +x /usr/local/bin/ftest
WORKDIR /work
ENTRYPOINT ["ftest"]
CMD ["run"]
