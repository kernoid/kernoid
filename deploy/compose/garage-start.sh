#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Starts Garage and sets up what kernoid needs: a one-node layout, the access key from .env and the bucket "kernoid".
# Each step is skipped when it is already done, so restarts do no harm. /tmp/ready marks the end (health check).
set -eu
rm -f /tmp/ready
garage server &
server=$!
trap 'kill -TERM "$server"' TERM INT

until garage status >/dev/null 2>&1; do sleep 1; done
if garage status | grep -q 'NO ROLE ASSIGNED'; then
    node=$(garage node id -q | cut -d@ -f1)
    garage layout assign -z local -c "${GARAGE_CAPACITY:-100G}" "$node"
    garage layout apply --version 1
fi
garage key info kernoid >/dev/null 2>&1 || garage key import --yes -n kernoid "$S3_ACCESS_KEY_ID" "$S3_SECRET_KEY"
garage bucket info kernoid >/dev/null 2>&1 || garage bucket create kernoid
garage bucket allow --read --write --owner kernoid --key kernoid
touch /tmp/ready

# The first wait ends when a signal arrives, the second when Garage has stopped.
wait "$server" || wait "$server"
