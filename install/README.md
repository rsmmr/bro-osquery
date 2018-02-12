# Install Summary #

## 1. Osquery

### Code Base

The most recent development is located in the [osquery fork by iBigQ](https://github.com/iBigQ/osquery).

```
git clone --recursive https://github.com/iBigQ/osquery -b bro_integration_actor
cd osquery
make deps
make && sudo make install
```

Compared to osquery's upstream "bro-integration" branch, the version
in this branch includes (1) updating to osquery version 2.11.2
(submitted as [PR
#4093](https://github.com/facebook/osquery/pull/4093); (2) switch to
the new Broker API; and (3) switch to CAF 0.15.5.

## 2. Bro

### CAF Dependency

```
git clone --recursive https://github.com/actor-framework/actor-framework 0.15.5
cd actor-framework
./configure && make && sudo make install
```

### Code Base

Build Bro with the new Broker version:

```
git clone --recursive https://github.com/bro/bro -b topic/actor-system
cd bro
./configure && make && sudo make install
```

### Bro Scripts

The Bro scripts have to be extended to talk to osquery hosts. Please
find the scripts in the [bro-osquery fork by
iBigQ](https://github.com/iBigQ/bro-osquery) repository under the
branch
[`bro-osquery-actor`](https://github.com/iBigQ/bro-osquery/tree/bro-osquery-actor).
