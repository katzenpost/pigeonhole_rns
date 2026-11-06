// -*- mode: Bluespec; -*-
// The Python replica (pigeonhole_rns/replica.py, rnsio.py, channel.py) on Python RNS, and a
// client talking to it in both query modes.
//
// The Python replica runs on OS threads, not asyncio: RNS starts a thread per request and per
// timeout callback, and the replica runs CHANNEL_WORKERS threads per Link. Threads interleave
// at any bytecode, so each action here is the code between two points where another thread can
// observe it: a packet on the wire, a list append, a lock or queue operation.
//
// Mode 1 (Link requests). RNS's Link.request transmits the request packet, then creates its
// PacketReceipt under Transport.receipts_lock (contended by the receipt sweep) and only then
// appends the RequestReceipt to link.pending_requests. A response arriving in between is
// dropped by Link.handle_response, which finds no pending request, and the caller waits its
// whole request timeout (60 s). The fix stashes such a response and the caller looks there
// once link.request returns.
//
// Mode 2 (Channel). A worker thread answers a query with Endpoint.send, which waits for the
// Channel window. Under load Transport keeps at most 1024 receipts and culls the oldest; a
// culled receipt of an envelope still in the Channel's TX ring makes RNS's is_ready_to_send
// raise on every call, for good. The exception killed the worker thread, so the Link's queue
// was never drained again and every later query on that Link hung. The fix tears the Link
// down instead, so the client opens a fresh one and asks again.
module python_replica {
  const FIXED: bool
  // The client's requests in mode 1 and queries in mode 2, the replica's worker threads on a
  // Link, and the Channel window.
  const REQS: Set[int]
  const QUERIES: Set[int]
  const WORKERS: Set[int]
  const WINDOW: int
  // How many Channel receipts Transport may cull in a behaviour.
  const CULLS: int

  // Mode 1: "idle", "sent" (packet on the wire, not yet in pending_requests), "registered",
  // "done".
  type Req = { phase: str, answered: bool, respInFlight: bool, stashed: bool, dropped: bool }
  // Mode 2: "idle", "waiting" (sent on the open Link), "done", "failed" (the Link closed under it).
  // env is the reply's Channel envelope: "none", "sent", "culled".
  type Query = { st: str, env: str }
  // A worker thread: "idle", "busy" (handling q), "dead" (killed by an exception), "gone"
  // (exited with its Link).
  type Worker = { st: str, q: int }
  type State = {
    reqs: int -> Req,
    queries: int -> Query,
    workers: int -> Worker,
    queue: Set[int],
    linkOpen: bool,
    culls: int,
  }

  var s: State

  pure val freshWorker: Worker = { st: "idle", q: 0 }

  // ---- functional layer ----

  pure def outstanding(st: State): int =
    st.queries.keys().filter(q => st.queries.get(q).env == "sent").size()

  pure def anyCulled(st: State): bool =
    st.queries.keys().exists(q => st.queries.get(q).env == "culled")

  // The Link closes: queries on it fail, its queue and TX ring go, its worker threads exit.
  pure def teardown(st: State): State = {
    ...st,
    linkOpen: false,
    queue: Set(),
    queries: st.queries.keys().mapBy(q =>
      val x = st.queries.get(q)
      if (x.st == "waiting") { st: "failed", env: "none" } else { ...x, env: "none" }),
    workers: st.workers.keys().mapBy(_ => { st: "gone", q: 0 }),
  }

  // ---- mode 1 ----

  // Link.request: the request packet goes out (RNS Transport.outbound transmits, then makes the receipt).
  action reqTransmit(r: int): bool = all {
    s.reqs.get(r).phase == "idle",
    s' = { ...s, reqs: s.reqs.setBy(r, x => { ...x, phase: "sent" }) },
  }

  // The replica's request handler thread answers; the response packet is in flight.
  action reqAnswer(r: int): bool = all {
    s.reqs.get(r).phase != "idle",
    not(s.reqs.get(r).answered),
    s' = { ...s, reqs: s.reqs.setBy(r, x => { ...x, answered: true, respInFlight: true }) },
  }

  // RequestReceipt.__init__ appends itself to link.pending_requests; with the fix, rnsio then
  // takes a response stashed before that.
  action reqRegister(r: int): bool = all {
    s.reqs.get(r).phase == "sent",
    s' = { ...s, reqs: s.reqs.setBy(r, x =>
      if (FIXED and x.stashed) { ...x, phase: "done", stashed: false } else { ...x, phase: "registered" }) },
  }

  // Link.handle_response on its own thread: completes a pending request, or else drops the
  // response; with the fix the wrapper stashes it under rnsio's lock.
  action reqDeliver(r: int): bool = all {
    s.reqs.get(r).respInFlight,
    s' = { ...s, reqs: s.reqs.setBy(r, x =>
      if (x.phase == "registered") { ...x, respInFlight: false, phase: "done" }
      else if (FIXED) { ...x, respInFlight: false, stashed: true }
      else { ...x, respInFlight: false, dropped: true }) },
  }

  // ---- mode 2 ----

  // Links.channel_request: the query's frames reach the Link's queue (Endpoint accept). A failed
  // query is asked again.
  action qSend(q: int): bool = all {
    s.linkOpen,
    Set("idle", "failed").contains(s.queries.get(q).st),
    s' = { ...s, queue: s.queue.union(Set(q)), queries: s.queries.setBy(q, x => { ...x, st: "waiting" }) },
  }

  // Links._link: a new Link, and Replica._on_link starts its worker threads.
  action linkOpen: bool = all {
    not(s.linkOpen),
    s.queries.keys().exists(q => s.queries.get(q).st == "failed"),
    s' = { ...s, linkOpen: true, workers: s.workers.keys().mapBy(_ => freshWorker) },
  }

  // work(): queries.get().
  action wTake(w: int, q: int): bool = all {
    s.linkOpen,
    s.workers.get(w).st == "idle",
    s.queue.contains(q),
    s' = { ...s, queue: s.queue.exclude(Set(q)), workers: s.workers.set(w, { st: "busy", q: q }) },
  }

  // Endpoint.send with room in the window: the reply goes out and reaches the client.
  action wSendOk(w: int): bool = {
    val q = s.workers.get(w).q
    all {
      s.linkOpen,
      s.workers.get(w).st == "busy",
      not(anyCulled(s)),
      outstanding(s) < WINDOW,
      s' = { ...s,
        queries: s.queries.set(q, { st: "done", env: "sent" }),
        workers: s.workers.set(w, freshWorker) },
    }
  }

  // Endpoint.send while the TX ring holds a culled receipt: is_ready_to_send raises. Before the
  // fix the exception ends the worker thread; with it the Link is torn down.
  action wSendRaises(w: int): bool = all {
    s.linkOpen,
    s.workers.get(w).st == "busy",
    anyCulled(s),
    s' = if (FIXED) teardown(s) else { ...s, workers: s.workers.setBy(w, x => { ...x, st: "dead" }) },
  }

  // The delivery proof of a reply envelope: RNS drops it from the TX ring, opening the window.
  action proof(q: int): bool = all {
    s.queries.get(q).env == "sent",
    s' = { ...s, queries: s.queries.setBy(q, x => { ...x, env: "none" }) },
  }

  // Transport culls the receipt of an envelope still awaiting its proof; the proof that comes
  // later is ignored, so the envelope never leaves the ring.
  action cull(q: int): bool = all {
    s.culls > 0,
    s.queries.get(q).env == "sent",
    s' = { ...s, culls: s.culls - 1, queries: s.queries.setBy(q, x => { ...x, env: "culled" }) },
  }

  action init: bool = all {
    s' = {
      reqs: REQS.mapBy(_ => { phase: "idle", answered: false, respInFlight: false, stashed: false, dropped: false }),
      queries: QUERIES.mapBy(_ => { st: "idle", env: "none" }),
      workers: WORKERS.mapBy(_ => freshWorker),
      queue: Set(),
      linkOpen: true,
      culls: CULLS,
    },
  }

  action step: bool = any {
    nondet r = REQS.oneOf()
    any { reqTransmit(r), reqAnswer(r), reqRegister(r), reqDeliver(r) },
    nondet q = QUERIES.oneOf()
    nondet w = WORKERS.oneOf()
    any { qSend(q), wTake(w, q), wSendOk(w), wSendRaises(w), proof(q), cull(q), linkOpen },
  }

  // ---- properties ----

  // A response that reached the client is never thrown away while its caller still waits.
  val noLostResponse: bool = REQS.forall(r => not(s.reqs.get(r).dropped))
  // Every worker thread of an open Link is alive to drain its queue.
  val workersAlive: bool = s.linkOpen implies WORKERS.forall(w => s.workers.get(w).st != "dead")
  val safe: bool = noLostResponse and workersAlive

  val allAnswered: bool =
    REQS.forall(r => s.reqs.get(r).phase == "done") and QUERIES.forall(q => s.queries.get(q).st == "done")
  // Without a timeout firing, every request and query is answered.
  temporal liveness = step.weakFair(Set(s)) implies eventually(allAnswered)

  // Witnesses: the race and the cull are reachable.
  val wRace: bool = REQS.exists(r => s.reqs.get(r).phase == "sent" and not(s.reqs.get(r).respInFlight) and s.reqs.get(r).answered)
  val wCulled: bool = anyCulled(s)
  val wTornDown: bool = not(s.linkOpen)
}

module python_replica_main {
  import python_replica(FIXED = false, REQS = Set(1), QUERIES = Set(1, 2), WORKERS = Set(1, 2), WINDOW = 2, CULLS = 1).*
}

module python_replica_fixed {
  import python_replica(FIXED = true, REQS = Set(1), QUERIES = Set(1, 2), WORKERS = Set(1, 2), WINDOW = 2, CULLS = 1).*
}
