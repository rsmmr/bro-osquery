#! /usr/bin/env bash

# Cannot run auditd in parallel, turn it off.
test -e /etc/init.d/auditd && service auditd status >/dev/null && service auditd stop && chkconfig auditd off

chkconfig osqueryd on
service osqueryd start

