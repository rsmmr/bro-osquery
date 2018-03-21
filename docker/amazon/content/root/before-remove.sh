#! /usr/bin/env bash

test -e /etc/init.d/osqueryd && service osqueryd status >/dev/null && chkconfig osqueryd off && service osqueryd stop
