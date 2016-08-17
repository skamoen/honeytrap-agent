FROM debian:sid

RUN apt-get update && \
   apt-get install -y dpkg-dev debhelper dh-golang golang-go golang-goprotobuf-dev && \
   rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

