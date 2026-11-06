# Quint model of the Python replica

`python_replica.qnt` models the replica's threads and Python RNS's Link requests and Channel
(`replica.py`, `rnsio.py`, `channel.py`): a mode 1 request whose response arrives before RNS
registers it, and mode 2 worker threads answering through a Channel whose receipt Transport may
cull. `python_replica_main` is the code before the fix, `python_replica_fixed` after it.

    quint run python_replica.qnt --main python_replica_fixed --invariant safe --witnesses wRace wCulled wTornDown
    quint verify python_replica.qnt --main python_replica_main --backend tlc --invariant noLostResponse
    quint verify python_replica.qnt --main python_replica_fixed --backend tlc --temporal liveness

`--backend tlc` compiles the module to TLA+ and runs TLC on it; `quint compile --target tlaplus
--main <module>` prints the TLA+. On `python_replica_main` TLC finds a counterexample to
`noLostResponse`, `workersAlive` and `liveness`; on `python_replica_fixed` all three hold.

Not modelled: forwarding, sync and push, which send through the same `Endpoint.send`; Resources;
timeouts, which are the hang itself.
