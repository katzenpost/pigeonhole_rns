# Quint model of the Rust replica

`rust_replica.qnt` models mode 2 on one Link of the Rust replica (`src/replica.rs`
`serve_channel`, `src/mesh.rs` `send_frames`) on tokio's multi-threaded runtime: worker tasks
sending through Reticulum-rs's Channel, which holds its `outbound` tokio Mutex across a transmit,
and the Channel's watcher task, which takes delivery proofs from a Link event broadcast of 16
slots shared by every Link and ends when it lags. `rust_replica_main` is the code before the
fix, `rust_replica_fixed` after it.

    quint run rust_replica.qnt --main rust_replica_fixed --invariant windowExact --witnesses wLagged wAnswered
    quint verify rust_replica.qnt --main rust_replica_main --backend tlc --temporal liveness
    quint verify rust_replica.qnt --main rust_replica_fixed --backend tlc --temporal liveness

`--backend tlc` compiles the module to TLA+ and runs TLC on it; `quint compile --target tlaplus
--main <module>` prints the TLA+. `windowDrains`, Reticulum-rs's own property, fails in both
modules, since the watcher still ends; `liveness` fails before the fix and holds after it.

Not modelled: the bridge's `spawn_blocking` socket calls and the store's std Mutex, which hold no
lock across an `.await`; the query queue's drops, which a lone client's window of 8 cannot cause.
