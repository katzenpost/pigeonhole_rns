# replica_rns

A Pigeonhole storage replica daemon for Reticulum mesh networks, in pure
Python on the RNS library. It stores boxes, replicates them to the other
replicas it hears, and is the mesh half of a bridge to a Katzenpost mixnet.
Pigeonhole is the protocol; clients live elsewhere, such as the group chat
client [katzenrns](https://github.com/katzenpost/katzenrns). The design is the Pigeonhole over Reticulum specification on the
Katzenpost website; this is its open mesh profile.

A replica is any node that announces `pigeonhole.replica`. Boxes are BACAP
boxes verified with `hpqc.bacap`, the same object the mixnet stores.

## Mesh modes

**Open** (the default, `--mesh-mode open`): full replication, no sharding.
Every replica stores every box. A replica that stores a new box, from a
client, a forward, or a read, forwards it to every replica it has heard but
the one it came from, retrying until each acknowledges; a box it already
holds is not passed on again. When a replica first hears another, and again
after it was unreachable or either restarted, the two sync: they walk the
Box ID space in pages of up to 128 IDs, each side enqueues for the other the
boxes it lacks, and a tombstone wins over the box it replaces. Reads are
served from the local store first. Replicas identify on the Links they open
to each other, so a forward's sender is known.

**Closed** (future): sharded. Boxes are placed by rendezvous hashing over
the replicas a node has heard, two owners per box; an entry replica stores
a client's write, acknowledges, and forwards along the box's order,
standing in for owners it cannot reach and handing off, then dropping its
copy, when it can. Reads walk the order past the owners. `--mesh-mode
closed` runs this placement today, but a closed mesh also needs out of band
authentication of its replicas, which is not implemented.

In both modes boxes crossing a bridge are sharded on the Katzenpost side,
as the mixnet places them.

## Bridges

A bridge is a replica like any other: it stores every box and syncs. It
also announces which mixnet it serves, as an id: the first 16 bytes of the
SHA-256 of `--mixnet`, a name such as the mixnet's PKI identity, the same on
every bridge to that mixnet. On top of replication:

- Each bridge writes each box it stores into its mixnet. Bridges serving
  the same mixnet ask each other first (path `pushed`): the first in the
  box's order among them writes, the others wait up to three retries for
  it and write themselves if it has not. A duplicate write is harmless.
- A box a bridge pulls from its mixnet is stored with that mixnet as its
  origin and replicates with it (path `forward`, the write prefixed with
  the origin), so no bridge writes it back there, while bridges to other
  mixnets do. One mesh links several mixnets without loops.
- A read that misses on a replica asks every replica it reaches, bridges
  asking their mixnets; the bridge that finds a box stores it and it
  replicates from there.

`--forward all` (the default) writes every box into the mixnet;
`--forward on-request` writes only boxes clients write to this bridge,
while it still pulls for reads. A tombstone written directly on a mixnet
does not cross to the mesh, since the bridge socket returns a tombstone
without its signature; one written on the mesh reaches every mixnet.

The mixnet half of the bridge, a unix socket on the Katzenpost replica, is in
the Katzenpost repository (`replica/bridge.go`).

## Query modes

A client opens a Link to a replica's `pigeonhole.replica` destination and
sends each query in one of two modes. Both carry the same query and reply
bytes (`wire.py`) and one destination serves both. Replicas also use paths
`peek`, `sync`, `forward` and `pushed` between themselves. The client keeps
up to 8 queries in flight per Link, from callers on several threads, under
a replica's mode 2 queue of 16.

1. **Requests.** Each query is a Link request to path `write` or `read`;
   one over the Link MDU travels as a Resource.
2. **Channel.** Each query and reply is a run of Channel messages on the
   Link, for Reticulum stacks with Links and Channel but no Link requests
   or Resources. The message's first byte picks the handler: 0 a read and 1
   a write query, as they begin, and 2 `peek`, 3 `sync`, 4 `forward` and 5
   `pushed`, followed by that path's request bytes and answered with its
   response bytes.

The announce's app data is one byte of flags: bit 0 says the replica is a
bridge, bit 1 that it serves mode 2, bit 2 that it serves the replica paths
in mode 2 too, and bit 3 that it serves no Link requests. A bridge follows it
with its 16 byte mixnet id; one announcing none serves the mixnet of the
empty name. A client in mode 2 uses only replicas announcing bit 1.

Replicas ask each other in mode 2 first, when the other announces bit 2 (bit
1 for a write), and as a Link request when it does not or mode 2 fails. One
announcing bit 3, such as the Rust replica on Reticulum-rs, is asked only in
mode 2, by replicas and by mode 1 clients alike. Python replicas serve both
modes.

### Channel framing

Every mode 2 message is one Channel message of MSGTYPE `0x5048`:

    request id   u16, big endian
    piece index  u8
    piece count  u8
    piece        the rest

A query or reply is cut into 1 to 255 pieces of at most the Channel MDU
minus 4 bytes, the Channel MDU being the Link MDU minus Channel's 6 byte
envelope: 421 bytes on a 500 byte MTU link. The receiver reassembles by
request id and drops a request whose pieces disagree on the count, or that
is incomplete after 60 seconds. A reply carries its query's request id.

A replica handles mode 2 queries on 2 worker threads per Link, with up to
16 more queued per Link and at most 32 handled at once across the replica.
A query arriving to a full queue is dropped; the client times out and asks
again.

### Bytes on the wire

Link packet bytes sent and received by a client for one 1000 byte box (a
1117 byte write query), measured by `tests/e2e_two_replicas.py --box-size
1000` on a warm Link:

| link MTU | operation | mode 1 sent / received | mode 2 sent / received |
|---|---|---|---|
| 500   | write | 1484 / 297 | 1468 / 428 |
| 500   | read  | 329 / 1436 | 480 / 1456 |
| 16384 | write | 1219 / 99  | 1318 / 198 |
| 16384 | read  | 131 / 1187 | 250 / 1306 |

At 500 bytes mode 1 sends a Resource (advertisement, parts, proof) and
mode 2 three frames, each with its own delivery proof. Over the namenlos
bridge (145 ms ping) that doubles a box query, 310 ms against 155 ms, so
leave Reticulum's `link_mtu_discovery` on where the interfaces allow it.

## Install

A Linux x86_64 executable, a wheel and an sdist are attached to each
[release](https://github.com/katzenpost/pigeonhole_rns/releases). From source:

    pip install -e .          # brings rns and the hpqc Python port from PyPI

## Run a replica

    replica_rns --config ~/.reticulum --box-size 1000 replica --storage ~/pigeonhole

`--box-size` is the box plaintext size and must be the same on every replica
and, through a bridge, equal to the mixnet's. A bridge adds
`--bridge-socket /path/to/replica/bridge.sock`, the `BridgeSocket` of a
Katzenpost replica on the same host, and `--mixnet <name>` and `--forward`
(see Bridges).

### Epochs and garbage collection

Boxes are kept by replica epoch, as on Katzenpost replicas: an epoch is
`--epoch-period` seconds (1200, Katzenpost's 20 minutes), a replica epoch
is `--replica-epoch-epochs` of them (504, a week), both counted from
2017-06-01 UTC. A box is stamped with the replica epoch it arrived in and
kept for that epoch and the next, so one to two weeks; GC runs at start and
at each replica epoch boundary. The bridge socket carries no timing and
Katzenpost's replica epoch is fixed at a week, so a bridge should keep the
defaults; it warns if it does not.

### Storage limits

Storage is optimistic: every box is stored while there is room.
`--max-storage-mib` caps the box database and its WAL on disk (0, the
default, for no cap), and `--min-free-storage-mib` keeps that much free on
its filesystem (500 by default, as Katzenpost's `MinFreeStorageMiB`). A new
box that would cross either limit first evicts the oldest boxes, by replica
epoch then arrival, tombstones only after every box, until 1/16 of the limit
is spare, and logs how many went. Only when nothing is left to evict is
the write refused with `STORAGE_FULL`. Evicted pages are handed back to the
filesystem (SQLite incremental vacuum and a WAL checkpoint), so the limits
measure real disk use; an older store is vacuumed once on start to allow
this.

## The Rust replica

`rust/` is the same replica in Rust on
[Reticulum-rs](https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs), at
the revision `katzenpost/pigeonhole_protocols` uses, with BACAP from the Rust
`hpqc`. It keeps the store (the same SQLite file), open and closed mesh
modes, sync, the bridge and its rules, the identity file and the command
line, and reads the TCP and UDP interfaces and `enable_transport` of a
Reticulum config file. Reticulum-rs has Links and Channel but no Link
requests or Resources, so it speaks mode 2 alone, to clients and replicas,
and announces bits 1, 2 and 3; Python replicas ask it in mode 2.

    cd rust && cargo build --release
    rust/target/release/replica_rns-rs --config ~/.reticulum --box-size 1000 replica --storage ~/pigeonhole

It asks other replicas in mode 2, so reaches those announcing bit 2. With the
optional feature `reticulum-py` it also falls back to Link requests and
Resources through Python RNS, embedded, for replicas that do not announce bit
2 or when mode 2 fails, as Python replicas do:

    cd rust && PYO3_PYTHON=$(which python) cargo build --release --features reticulum-py
    rust/target/release/replica_rns-rs --config ~/.reticulum replica --storage ~/pigeonhole --py-config ~/.reticulum-py

`--py-config` is the config directory of the Python Reticulum instance, with
interfaces of its own, such as a TCP client of this replica's listener; RNS
and this package must be importable by that Python.

## Check a replica

These commands write and read single boxes, to test replicas:

    replica_rns new-cap
    replica_rns --config ~/.reticulum write --writecap <hex> --index 0 "yo what up"
    replica_rns --config ~/.reticulum read  --readcap <hex>  --index 0
    replica_rns --config ~/.reticulum read  --readcap <hex>  --index 0 --mode channel

## Test

    pytest
    python tests/e2e_two_replicas.py --run-dir /some/scratch/dir
    python tests/e2e_two_replicas.py --run-dir /some/scratch/dir --box-size 1000 --mtu-discovery no

`tests/e2e_replication.py` (`-n 5 --topo line`, say) starts N replicas in a
mesh or a line, holds the last back until boxes are written, stops replica 1
while more are written, then tombstones half, and passes when every replica
holds every box or its tombstone. `--rust 1,3` runs those replicas with the
Rust replica (`--rust-bin`, by default `rust/target/release/replica_rns-rs`).

The end to end test starts two replica processes on a local TCP interface
and drives a client through write, read, forward, delete and tombstone in
mode 1, then write, read, delete and tombstone in mode 2 with boxes crossing
between the modes, and prints the bytes each mode puts on the link.

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
