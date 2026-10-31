#!/bin/sh
# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
#
# The mesh side of a bridge to a Katzenpost docker mixnet: a container on the
# host network running a mesh replica bridged to replica$BRIDGE_REPLICA
# through the unix socket in that replica's DataDir, and the bot that answers
# the jobs Katzenpost's client docker test drops into NET_DIR/reticulum/jobs.
#
#   tests/docker_bridge.sh start NET_DIR [BRIDGE_REPLICA]   build the image and start the container
#   tests/docker_bridge.sh test  NET_DIR [BRIDGE_REPLICA]   start, then run TestReticulumBridge in katzenpost/client
#   tests/docker_bridge.sh logs  NET_DIR
#   tests/docker_bridge.sh stop  NET_DIR
#
# NET_DIR is the mixnet's directory in the Katzenpost checkout, such as
# katzenpost/docker/mixnet-alpine, made by `make -C docker start wait` there
# (whose genconfig gives replica1 a bridge socket by default).
set -eu
cmd=${1:?start, test, logs or stop}
net=$(cd "${2:?NET_DIR}" && pwd)
bridge_replica=${3:-1}
here=$(cd "$(dirname "$0")/.." && pwd)
docker=${DOCKER:-$(command -v podman >/dev/null 2>&1 && echo podman || echo docker)}
case "$docker" in *podman) user=0:0 ;; *) user=$(id -u):$(id -g) ;; esac
net_name=$(basename "$net")
distro=${net_name#mixnet-}
image=pigeonhole-rns-bridge
container=pigeonhole_rns_bridge_$(printf '%s' "$net" | cksum | cut -d' ' -f1)

start() {
  "$docker" build -q -t "$image" -f "$here/Dockerfile" "$here" >/dev/null
  mkdir -p "$net/reticulum/rns" "$net/reticulum/jobs" "$net/reticulum/store"
  "$docker" rm -f "$container" >/dev/null 2>&1 || true
  "$docker" run -d --name "$container" --network=host --user "$user" \
    --volume "$here:/pigeonhole_rns" --volume "$net:/$net_name" "$image" \
    sh /pigeonhole_rns/tests/docker_entry.sh "/$net_name" "$bridge_replica" >/dev/null
  echo "$container"
}

case "$cmd" in
  start) start ;;
  stop) "$docker" rm -f "$container" >/dev/null 2>&1 || true ;;
  logs) "$docker" logs "$container" ;;
  test)
    start
    sleep 5
    make -C "$net/../../client" distro="$distro" \
      reticulum_jobs="/go/katzenpost/docker/$net_name/reticulum/jobs" dockertest_reticulum
    ;;
  *) echo "unknown command $cmd" >&2; exit 2 ;;
esac
