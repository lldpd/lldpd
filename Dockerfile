FROM alpine:latest AS build
RUN apk add autoconf automake libtool \
	libevent-dev libxml2-dev jansson-dev \
        readline-dev libcap-dev bsd-compat-headers \
        alpine-sdk
WORKDIR /build
COPY . .
RUN ./autogen.sh
RUN ./configure \
		--prefix=/usr/local \
		--sysconfdir=/etc \
		--enable-pie \
		--enable-hardening \
		--without-embedded-libevent \
		--without-snmp \
                --with-xml \
		--with-privsep-user=_lldpd \
		--with-privsep-group=_lldpd \
		--with-privsep-chroot=/run/lldpd \
		--with-lldpd-ctl-socket=/run/lldpd.socket \
		--with-lldpd-pid-file=/run/lldpd.pid
RUN make
RUN make install DESTDIR=/lldpd

FROM alpine:latest
RUN apk add libevent libxml2 jansson readline libcap \
    && addgroup -S _lldpd \
    && adduser -S -G _lldpd -D -H -g "lldpd user" _lldpd
COPY --from=build /lldpd /
VOLUME /etc/lldpd.d
ENTRYPOINT ["lldpd", "-d"]
CMD []

