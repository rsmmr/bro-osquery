
all:

rpms: rpm-amazon

rpm-amazon:
	docker build -t bro-osquery amazon
	docker run --rm bro-osquery bash -c 'cd /root && tar cf - bro-osquery-*.rpm'  | tar xfv -
