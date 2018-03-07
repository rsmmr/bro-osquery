FROM amazonlinux:latest

RUN yum install -y git which sudo patch

## Install FPM
RUN yum install -y ruby ruby-devel autoconf autotools aclocal libtool rpm-build
RUN gem install --no-ri --no-rdoc fpm

## Cannot build as root, so the following is adapted from osquery's
## Dockerfile (original is for Debian).

RUN adduser -G wheel -c "" osquery && \
    mkdir -p /home/osquery && \
    sed -i.bak 's/^# \(%wheel.*NOPASSWD.*\)$/\1/g' /etc/sudoers && \
    mkdir -p /usr/local/osquery && \
    chown -R osquery /usr/local && \
    mkdir -p /home/osquery && \
    chown -R osquery /home/osquery

USER osquery
ENV HOME /home/osquery

WORKDIR /home/osquery
RUN git clone --recursive https://github.com/iBigQ/osquery -b osquery-bro-actor

WORKDIR /home/osquery/osquery
RUN make deps
RUN ./tools/provision.sh install osquery/osquery-local/caf
RUN ./tools/provision.sh install osquery/osquery-local/broker
RUN SKIP_BRO=False make -j 4

USER root
COPY --chown=root:root content/ /
RUN cp /home/osquery/osquery/build/amazon*/osquery/osqueryd /opt/osquery/bin
RUN cp /home/osquery/osquery/build/amazon*/osquery/osqueryi /opt/osquery/bin

WORKDIR /root
RUN /root/create-rpm
