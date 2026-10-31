# Pigeonhole over Reticulum

A Pigeonhole storage replica and client for Reticulum mesh networks, in pure
Python on the RNS library, and the mesh half of a bridge to a Katzenpost
mixnet. The design is the Pigeonhole over Reticulum specification on the
Katzenpost website; this is its open mesh profile.

A replica is any node that announces `pigeonhole.replica`. Boxes are placed
by rendezvous hashing over the replicas a node has heard, two owners per
box; an entry replica stores a client's write, acknowledges, and forwards
along the box's order, standing in for owners it cannot reach and handing
off when it can. Reads walk the order past the owners. Boxes are BACAP boxes
verified with `hpqc.bacap`, the same object the mixnet stores.

The mixnet half of the bridge, a unix socket on the Katzenpost replica, is in
the Katzenpost repository (`replica/bridge.go`); the group chat client for
the mesh is [katzenrns](https://github.com/katzenpost/katzenrns).

## Install

    pip install -e .          # brings rns and the hpqc Python port from PyPI

## Run a replica

    pigeonhole-rns --config ~/.reticulum --box-size 1000 replica --storage ~/pigeonhole

`--box-size` is the box plaintext size and must be the same on every replica
and, through a bridge, equal to the mixnet's. A bridge adds
`--bridge-socket /path/to/replica/bridge.sock`, the `BridgeSocket` of a
Katzenpost replica on the same host.

## Use it

    pigeonhole-rns new-cap
    pigeonhole-rns --config ~/.reticulum write --writecap <hex> --index 0 "yo what up"
    pigeonhole-rns --config ~/.reticulum read  --readcap <hex>  --index 0

## Test

    pytest
    python tests/e2e_two_replicas.py --run-dir /some/scratch/dir

The end to end test starts two replica processes on a local TCP interface
and drives a client through write, read, forward, delete and tombstone.

## Bridge test against the docker mixnet

With a Katzenpost checkout whose docker mixnet is up (`make -C docker start wait` there;
its genconfig gives replica1 a bridge socket in its DataDir by default):

    tests/docker_bridge.sh test  /path/to/katzenpost/docker/mixnet-alpine
    tests/docker_bridge.sh start /path/to/katzenpost/docker/mixnet-alpine   # just the container
    tests/docker_bridge.sh logs  /path/to/katzenpost/docker/mixnet-alpine
    tests/docker_bridge.sh stop  /path/to/katzenpost/docker/mixnet-alpine

`start` builds this repository's `Dockerfile` and runs a container on the host network with a
mesh replica bridged to replica1's socket and `tests/docker_bot.py`; `test` then runs
`TestReticulumBridge` in Katzenpost's `client/`: a mixnet client writes a box, drops a job for
the bot, the bot reads the box through the mesh (pulled over the bridge) and answers on another
stream (pushed over the bridge), and the mixnet client reads the answer.

The bridge socket's wire format and what a replica answers a write with are pinned by
`testdata/bridge_socket_vectors.json`, made by `tests/make_vectors.py`. `tests/test_bridge_vectors.py`
here and `replica/bridge_vectors_test.go` in Katzenpost both read it, and CI checks the two
copies are the same file.
