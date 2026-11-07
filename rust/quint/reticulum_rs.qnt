// -*- mode: Bluespec; -*-
// The Rust replica as it was on Reticulum-rs (rust/src/replica.rs serve_channel, mesh.rs send_frames),
// answering mode 2 queries on one in-Link.
//
// The replica runs on tokio's multi-threaded runtime: its CHANNEL_WORKERS worker tasks and
// Reticulum-rs's per-Channel watcher task run in parallel, and each action here is the code
// between two .await points (or two lock operations). Channel::send holds the Channel's
// `outbound` tokio Mutex across the packet's transmit, and the watcher takes the same Mutex
// for each delivery proof. The watcher reads proofs from the Transport's link event broadcast,
// whose 16 slots every Link's events share; a watcher that falls behind gets
// RecvError::Lagged, logs "may miss delivery proofs" and returns. Its Channel then never
// sees another proof, the window stays full, every send answers LinkNotReady, and the
// queries on that Link wait out their 60 s, then fill the queue ("queue full").
//
// The Channel's receiver task reads the Link's payloads from a broadcast too, and one it lags
// past is lost: a query frame lost there leaves a gap in the Channel's sequence, so it delivers
// no later message on that Link either.
//
// Reticulum-rs is not changed here. The fix in send_frames gives up once the window has made
// no progress for a stall bound, and serve_channel then closes the Link; a client whose query
// times out closes its Link too (rnsio.channel_request). Either way the client opens a fresh
// Link, with a fresh Channel and tasks, and asks again.
//
// Locks: outbound -> link and outbound -> transport handler inside Reticulum-rs, handler ->
// link when it routes packets; the replica's own std Mutexes (replies, flags, subs, pushers)
// are never held across an .await. That order is acyclic, so the model keeps only the one
// lock the wedge turns on, outbound.
module rust_replica {
  const FIXED: bool
  // A worker task per query, as each of the CHANNEL_WORKERS answers one at a time.
  const QUERIES: Set[int]
  const WINDOW: int
  // Broadcast slots, and how many other Links' events may arrive in a behaviour.
  const SLOTS: int
  const NOISE: int

  // A query: "net" (on its way to the replica), then its worker: "wait" (has a reply to send), "tx" (holds outbound, transmitting), "done".
  // A reply's proof: "none", "inflight" (on the wire back), "seen" (handled by the watcher).
  // The watcher: "recv", "lock" (has a proof, wants outbound), "dead".
  // Events in the broadcast: a query's proof, or 0 for another Link's event.
  type State = {
    worker: int -> str,
    proof: int -> str,
    outstanding: int,
    holder: int,
    watcher: str,
    ev: int,
    buf: List[int],
    lagged: bool,
    rxGap: bool,
    noise: int,
  }

  var s: State

  // Lock holders: 0 none, -1 the watcher, q a worker.
  pure val NONE: int = 0
  pure val WATCHER: int = -1

  // A broadcast send: when every slot is taken the oldest event is lost and the receiver lags.
  pure def publish(st: State, e: int): State =
    if (st.buf.length() < SLOTS) { ...st, buf: st.buf.append(e) }
    else { ...st, buf: st.buf.tail().append(e), lagged: true }

  // The Link closes and the client asks again on a new one.
  pure def reopen(st: State): State = {
    ...st,
    worker: st.worker.keys().mapBy(q => if (st.worker.get(q) == "done") "done" else "net"),
    proof: st.proof.keys().mapBy(_ => "none"),
    outstanding: 0, holder: NONE, watcher: "recv", ev: 0, buf: List(), lagged: false, rxGap: false,
  }

  // The Channel delivers the query to serve_channel's queue, unless a lost frame left a gap.
  action qArrive(q: int): bool = all {
    s.worker.get(q) == "net",
    not(s.rxGap),
    s' = { ...s, worker: s.worker.set(q, "wait") },
  }

  // spawn_receiver lags past the query's frame, with another Link's payloads crowding it out.
  action qLost(q: int): bool = all {
    s.worker.get(q) == "net",
    s.noise > 0,
    s' = { ...s, noise: s.noise - 1, rxGap: true },
  }

  // With the fix: the client's query times out with no answer coming, and it closes the Link.
  action clientTimeout: bool = all {
    FIXED,
    s.rxGap,
    QUERIES.exists(q => s.worker.get(q) == "net"),
    s' = reopen(s),
  }

  // send_frames -> Channel::send: outbound.lock().await, then is_ready_to_send. A full window
  // answers LinkNotReady and the worker sleeps and retries, so it only gets past here with room.
  action wLock(q: int): bool = all {
    s.worker.get(q) == "wait",
    s.holder == NONE,
    s.outstanding < WINDOW,
    s' = { ...s, holder: q, worker: s.worker.set(q, "tx"), outstanding: s.outstanding + 1 },
  }

  // outlet_send(...).await with outbound held: the reply reaches the client, its proof is on
  // the way back, and outbound is released.
  action wTx(q: int): bool = all {
    s.worker.get(q) == "tx",
    s' = { ...s, holder: NONE, worker: s.worker.set(q, "done"), proof: s.proof.set(q, "inflight") },
  }

  // The Transport receives the proof and broadcasts the Link event.
  action peerProof(q: int): bool = all {
    s.proof.get(q) == "inflight",
    s' = publish({ ...s, proof: s.proof.set(q, "seen") }, q),
  }

  // Another Link's event on the shared broadcast.
  action otherLink: bool = all {
    s.noise > 0,
    s' = publish({ ...s, noise: s.noise - 1 }, 0),
  }

  // spawn_watch_outbound: out_link_events.recv().await. Lagged ends the task.
  action watcherRecv: bool = all {
    s.watcher == "recv",
    s.lagged or s.buf.length() > 0,
    s' = if (s.lagged) { ...s, watcher: "dead" }
         else if (s.buf.head() == 0) { ...s, buf: s.buf.tail() }
         else { ...s, buf: s.buf.tail(), watcher: "lock", ev: s.buf.head() },
  }

  // outbound.lock().await.handle_proof(hash): the envelope leaves the window.
  action watcherProof: bool = all {
    s.watcher == "lock",
    s.holder == NONE,
    s' = { ...s, watcher: "recv", ev: 0, outstanding: s.outstanding - 1 },
  }

  // With the fix: send_frames sees no window progress for the stall bound (no proof can come:
  // the watcher is gone) and serve_channel closes the Link.
  action stallClose: bool = all {
    FIXED,
    s.watcher == "dead",
    QUERIES.exists(q => s.worker.get(q) == "wait"),
    s.outstanding >= WINDOW,
    s' = reopen(s),
  }

  action init: bool = all {
    s' = {
      worker: QUERIES.mapBy(_ => "net"),
      proof: QUERIES.mapBy(_ => "none"),
      outstanding: 0, holder: NONE, watcher: "recv", ev: 0, buf: List(), lagged: false, rxGap: false, noise: NOISE,
    },
  }

  action step: bool = any {
    nondet q = QUERIES.oneOf()
    any { qArrive(q), qLost(q), wLock(q), wTx(q), peerProof(q) },
    clientTimeout,
    otherLink,
    watcherRecv,
    watcherProof,
    stallClose,
  }

  // ---- properties ----

  // Every reply envelope in the window still has a proof that the watcher will handle.
  val windowDrains: bool =
    s.outstanding > 0 implies s.watcher != "dead"
  // The window counts exactly the envelopes awaiting a proof the watcher has not handled,
  // until the broadcast loses one.
  val windowExact: bool =
    s.outstanding == QUERIES.filter(q => s.worker.get(q) == "tx" or s.proof.get(q) == "inflight").size()
      + s.buf.select(e => e != 0).length() + (if (s.watcher == "lock") 1 else 0)
      or s.lagged or s.watcher == "dead"

  val allAnswered: bool = QUERIES.forall(q => s.worker.get(q) == "done")
  temporal liveness = step.weakFair(Set(s)) implies eventually(allAnswered)

  val wLagged: bool = s.watcher == "dead"
  val wGap: bool = s.rxGap
  val wAnswered: bool = allAnswered
}

module rust_replica_main {
  import rust_replica(FIXED = false, QUERIES = Set(1, 2), WINDOW = 1, SLOTS = 1, NOISE = 1).*
}

module rust_replica_fixed {
  import rust_replica(FIXED = true, QUERIES = Set(1, 2), WINDOW = 1, SLOTS = 1, NOISE = 1).*
}
