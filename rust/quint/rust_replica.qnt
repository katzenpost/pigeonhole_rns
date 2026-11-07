// -*- mode: Bluespec; -*-
// The Rust replica (rust/src/net.rs, replica.rs) on berlinmesh/reticulum, answering mode 2
// queries on one in-Link.
//
// The stack is sans-IO and runs on one thread, the core: it alone holds the Channel's send
// window, its queued frames and its receive order, and it handles a delivery proof in the same
// step that reads the packet off the interface. The replica's worker tasks (tokio, in
// parallel with the core) hand each reply to the core on an unbounded command queue and never
// touch the Channel. There is no event broadcast to lag and no lock held across a send, so the
// Reticulum-rs wedge (a watcher task ending on a lagged broadcast, the window never draining)
// has nothing to happen in.
//
// What can still go wrong is the network: a reply's packet or its proof is lost. The core
// sends the envelope again on its timeout (reticulum_channel::Tx::poll), up to MAX_TRIES sends,
// and then tears the Link down; the client opens a fresh one and asks again. Query frames the
// client sends are delivered in order by the client's own Channel, which resends what this
// side refused or never proved, so a query is modelled as arriving or not yet arriving.
//
// Each action is one turn of the core loop or one step of a worker between .await points.
module rust_replica {
  // A query per worker turn, as each of the CHANNEL_WORKERS answers one at a time.
  const QUERIES: Set[int]
  const WINDOW: int
  const MAX_TRIES: int
  // Packets the network may lose in a behaviour, so the Link can still make progress.
  const LOSSES: int

  // A query: "net" (on its way), "work" (a worker handles it), "cmd" (its reply is on the
  // command queue), "queued" (frames wait for the window), "sent" (in the window), "done".
  // Its envelope's last copy: "none", "inflight" (it or its proof on the wire), "lost".
  type State = {
    query: int -> str,
    copy: int -> str,
    tries: int -> int,
    outstanding: int,
    cmds: List[int],
    losses: int,
    teardowns: int,
  }

  var s: State

  pure def inWindow(st: State, q: int): bool = st.query.get(q) == "sent"

  // The Link closes; the client opens a new one and asks again what it has no answer to.
  pure def reopen(st: State): State = {
    ...st,
    query: st.query.keys().mapBy(q => if (st.query.get(q) == "done") "done" else "net"),
    copy: st.copy.keys().mapBy(_ => "none"),
    tries: st.tries.keys().mapBy(_ => 0),
    outstanding: 0,
    cmds: List(),
    teardowns: st.teardowns + 1,
  }

  // The Channel delivers the query; the replica's event task puts it on the Link's queue,
  // where a worker takes it.
  action qArrive(q: int): bool = all {
    s.query.get(q) == "net",
    s' = { ...s, query: s.query.set(q, "work") },
  }

  // The worker's handler returns; it sends Cmd::Reply, which never blocks.
  action wReply(q: int): bool = all {
    s.query.get(q) == "work",
    s' = { ...s, query: s.query.set(q, "cmd"), cmds: s.cmds.append(q) },
  }

  // Core: the next command, the reply split into frames on the Channel's queue.
  action coreCmd: bool = all {
    s.cmds.length() > 0,
    s' = { ...s, query: s.query.set(s.cmds.head(), "queued"), cmds: s.cmds.tail() },
  }

  // Core: pump sends a queued envelope while the window has room.
  action corePump(q: int): bool = all {
    s.query.get(q) == "queued",
    s.outstanding < WINDOW,
    s' = { ...s, query: s.query.set(q, "sent"), copy: s.copy.set(q, "inflight"),
           tries: s.tries.set(q, 1), outstanding: s.outstanding + 1 },
  }

  // The envelope or its proof is lost on the way.
  action netLose(q: int): bool = all {
    s.copy.get(q) == "inflight",
    s.losses > 0,
    s' = { ...s, copy: s.copy.set(q, "lost"), losses: s.losses - 1 },
  }

  // Core: the proof comes in on an interface and settles the envelope, in the same turn.
  action coreProof(q: int): bool = all {
    s.copy.get(q) == "inflight",
    inWindow(s, q),
    s' = { ...s, query: s.query.set(q, "done"), copy: s.copy.set(q, "none"),
           outstanding: s.outstanding - 1 },
  }

  // Core: the envelope's timeout passes with no proof, and it is sent again.
  action coreResend(q: int): bool = all {
    s.copy.get(q) == "lost",
    s.tries.get(q) < MAX_TRIES,
    s' = { ...s, copy: s.copy.set(q, "inflight"), tries: s.tries.set(q, s.tries.get(q) + 1) },
  }

  // Core: MAX_TRIES sends went unproved, and the Link is torn down.
  action coreTeardown(q: int): bool = all {
    s.copy.get(q) == "lost",
    s.tries.get(q) >= MAX_TRIES,
    s' = reopen(s),
  }

  action init: bool = all {
    s' = {
      query: QUERIES.mapBy(_ => "net"),
      copy: QUERIES.mapBy(_ => "none"),
      tries: QUERIES.mapBy(_ => 0),
      outstanding: 0, cmds: List(), losses: LOSSES, teardowns: 0,
    },
  }

  action step: bool = any {
    nondet q = QUERIES.oneOf()
    any { qArrive(q), wReply(q), corePump(q), netLose(q), coreProof(q), coreResend(q), coreTeardown(q) },
    coreCmd,
  }

  // ---- properties ----

  // The window counts exactly the envelopes awaiting a proof, always: no proof is handled
  // anywhere but in the core, so none is missed.
  val windowExact: bool =
    s.outstanding == QUERIES.filter(q => inWindow(s, q)).size()
  val windowBound: bool = s.outstanding <= WINDOW
  // An envelope in the window has a copy on the wire or one the core will send again or
  // tear down for: the window always drains.
  val windowDrains: bool =
    QUERIES.forall(q => inWindow(s, q) implies s.copy.get(q) != "none")

  val allAnswered: bool = QUERIES.forall(q => s.query.get(q) == "done")
  temporal liveness = step.weakFair(Set(s)) implies eventually(allAnswered)

  val wFull: bool = s.outstanding == WINDOW
  val wResent: bool = QUERIES.exists(q => s.tries.get(q) > 1)
  val wTeardown: bool = s.teardowns > 0
  val wAnswered: bool = allAnswered
}

// Eight queries in flight, as a client's window of 8, on a window of 5.
module rust_replica_eight {
  import rust_replica(QUERIES = Set(1, 2, 3, 4, 5, 6, 7, 8), WINDOW = 5, MAX_TRIES = 5, LOSSES = 0).*
}

// Lost packets: resends, and a teardown when MAX_TRIES are lost.
module rust_replica_lossy {
  import rust_replica(QUERIES = Set(1, 2), WINDOW = 1, MAX_TRIES = 2, LOSSES = 3).*
}
