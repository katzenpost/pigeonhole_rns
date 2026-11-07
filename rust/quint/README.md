# Quint model of the Rust replica

`rust_replica.qnt` models mode 2 on one Link of the Rust replica on berlinmesh/reticulum
(`src/net.rs`, `src/replica.rs`): the stack thread, which alone holds the Channel's window,
queued frames and receive order and settles a delivery proof in the turn it reads it, and the
worker tasks, which hand replies to it on an unbounded command queue. The network may lose an
envelope or its proof; the stack thread sends it again on its timeout, up to `MAX_TRIES`
sends, then tears the Link down and the client asks again on a new one.
`rust_replica_eight` has 8 queries in flight, as a client's window of 8, on a window of 5;
`rust_replica_lossy` loses packets until resends and a teardown happen.

    quint run rust_replica.qnt --main rust_replica_lossy --invariant "windowExact and windowBound and windowDrains" --witnesses wFull wResent wTeardown wAnswered
    quint verify rust_replica.qnt --main rust_replica_eight --backend tlc --invariant "windowExact and windowBound and windowDrains" --temporal liveness
    quint verify rust_replica.qnt --main rust_replica_lossy --backend tlc --invariant "windowExact and windowBound and windowDrains" --temporal liveness

`--backend tlc` compiles the module to TLA+ and runs TLC on it. All three invariants and
`liveness` hold in both modules (5,575,776 distinct states for `rust_replica_eight`).

`reticulum_rs.qnt` is the replica as it was on Reticulum-rs: a Channel watcher task read
proofs from a 16 slot event broadcast that every Link shared and ended when it lagged; its
window then never drained, so queries in flight could wedge the Link, and `liveness` held
only with the replica closing a Link whose window stalled and the client (`rnsio`) one whose
query timed out (`--main rust_replica_main` fails, `--main rust_replica_fixed` holds). On
berlinmesh/reticulum there is no broadcast and no task between the interface and the window,
so that state does not exist. The client still closes such a Link, for replicas not yet
moved.

Not modelled: the bridge's `spawn_blocking` socket calls and the store's std Mutex, which hold no
lock across an `.await`; the query queue's drops, which a lone client's window of 8 cannot cause;
proof signatures, which the stack thread does not check (`net.rs`).
