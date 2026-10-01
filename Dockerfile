# syntax=docker/dockerfile:1
FROM alpine:3.22 AS build
RUN apk add --no-cache cmake ninja g++ pkgconf libsodium-dev sqlite-dev
WORKDIR /src
COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
COPY tests ./tests
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    && cmake --build build --parallel 2

FROM alpine:3.22
RUN apk add --no-cache libstdc++ libsodium sqlite-libs \
    && addgroup -S kairc \
    && adduser -S -G kairc -h /var/lib/kairc kairc \
    && mkdir -p /var/lib/kairc/data /etc/kairc \
    && chown -R kairc:kairc /var/lib/kairc
COPY --from=build /src/build/kaircd /usr/local/bin/kaircd
COPY config/kairc.conf.example /etc/kairc/kairc.conf
USER kairc:kairc
WORKDIR /var/lib/kairc
VOLUME ["/var/lib/kairc/data"]
ENTRYPOINT ["kaircd", "--config", "/etc/kairc/kairc.conf"]
