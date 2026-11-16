// Paging for the activity dialog, kept apart from the DOM so the tests can run
// it in a vm. The hazard it exists for: switching filter while a request for
// the old one is still out. Every call here is tagged with a generation; a
// reply that arrives after the filter changed, the dialog closed or a newer
// load started is dropped (the call resolves to null), and the request is
// aborted as well so it stops costing anything.
//
// fetchPage(type, before, signal) -> Promise<{ items, next }>
function makePager(fetchPage) {
  let gen = 0, busy = false;
  const live = new Set();                  // controllers of requests in flight
  const p = { type: 'all', next: null };

  const begin = (isLoad = true) => {
    const c = new AbortController();
    live.add(c);
    if (isLoad) busy = true;
    return { g: gen, signal: c.signal, done: () => live.delete(c) };
  };
  // Resolve a tagged fetch: null if it was superseded, whatever way it ended.
  async function run(g, done, job, isLoad = true) {
    try { const r = await job(); return g === gen ? r : null; }
    catch (e) { if (g !== gen) return null; throw e; }
    finally { done(); if (isLoad && g === gen) busy = false; }
  }

  // First page of a filter; supersedes everything in flight.
  p.start = (type) => {
    p.cancel();
    p.type = type;
    const { g, signal, done } = begin();
    return run(g, done, async () => {
      const j = await fetchPage(type, null, signal);
      if (g !== gen) return null;
      p.next = j.next;
      return { items: j.items };
    });
  };

  // The page after the one shown. Does nothing without a cursor, and nothing
  // while a load is already out, so a double click cannot add a page twice.
  p.more = () => {
    if (!p.next || busy) return Promise.resolve(null);
    const type = p.type, before = p.next, { g, signal, done } = begin();
    return run(g, done, async () => {
      const j = await fetchPage(type, before, signal);
      if (g !== gen) return null;
      p.next = j.next;
      return { items: j.items };
    });
  };

  // Every page of the filter that was current when this was called. Superseded
  // like any load: a filter change or close abandons it.
  p.all = () => {
    const type = p.type, { g, signal, done } = begin(false);
    return run(g, done, async () => {
      const items = [];
      let before = null;
      do {
        const j = await fetchPage(type, before, signal);
        if (g !== gen) return null;
        items.push(...j.items); before = j.next;
      } while (before);
      return { items, type };
    }, false);
  };

  // Close, or a new filter: abandon whatever is in flight.
  p.cancel = () => { gen++; for (const c of live) c.abort(); live.clear(); busy = false; p.next = null; };
  return p;
}
