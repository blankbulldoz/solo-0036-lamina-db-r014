package engine

import (
	"lamina/internal/cursor"
	"lamina/internal/datum"
	"lamina/internal/query"
	"time"
)

// Resource budgets for server-held traversal sessions. A cursor is a pinned
// snapshot plus a small resume record, not a materialized result set, so the
// cap mirrors the active-transaction budget rather than the row budgets.
const (
	maxCursors       = 128
	minCursorTTL     = 5 * time.Second
	maxCursorTTL     = time.Hour
	defaultCursorTTL = 10 * time.Minute
	sweepInterval    = 15 * time.Second
)

// cursorSession is the server-side half of an issued token. Cursors pin the
// vacuum horizon exactly like active transactions: a long-running traversal
// keeps every version its snapshot needs, and closing the cursor releases the
// pin. The position is only used to reject out-of-order token replay; the
// token itself remains the authoritative resume handle across restarts.
type cursorSession struct {
	id        string
	snapshot  uint64
	txn       string
	ttl       time.Duration
	expiresAt time.Time
	done      bool
	position  []datum.Value
}

// CursorPage is one delivered batch plus the next opaque token.
type CursorPage struct {
	Cursor        string      `json:"cursor,omitempty"`
	Done          bool        `json:"done"`
	Rows          []datum.Row `json:"rows"`
	Plan          query.Plan  `json:"plan"`
	Scanned       int         `json:"scanned"`
	Matched       int         `json:"matched"`
	PageSize      int         `json:"page_size"`
	Snapshot      uint64      `json:"snapshot"`
	ExpiresAt     string      `json:"expires_at"`
	RowsDelivered int         `json:"rows_delivered"`
	TTLSeconds    int64       `json:"ttl_seconds"`
}

// CursorSummary exposes held sessions through GET /stats.
type CursorSummary struct {
	ID        string `json:"id"`
	Snapshot  uint64 `json:"snapshot"`
	Txn       string `json:"transaction,omitempty"`
	Done      bool   `json:"done"`
	ExpiresAt string `json:"expires_at"`
}

func (d *DB) ttlDuration(seconds int) (time.Duration, error) {
	if seconds == 0 {
		return defaultCursorTTL, nil
	}
	ttl := time.Duration(seconds) * time.Second
	if ttl < minCursorTTL || ttl > maxCursorTTL {
		return 0, fault("invalid", "cursor ttl must be %d..%d seconds", int(minCursorTTL.Seconds()), int(maxCursorTTL.Seconds()))
	}
	return ttl, nil
}

// OpenCursor validates a read-only query request, pins the chosen snapshot
// and returns the first page together with a signed resume token.
func (d *DB) OpenCursor(q query.Request, ttlSeconds int) (CursorPage, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.usable(); err != nil {
		return CursorPage{}, err
	}
	if q.Aggregate != nil {
		return CursorPage{}, fault("invalid", "aggregates return a single row and cannot be paged")
	}
	ttl, err := d.ttlDuration(ttlSeconds)
	if err != nil {
		return CursorPage{}, err
	}
	r, plan, rows, keys, tx, err := d.snapshotRead(q)
	if err != nil {
		return CursorPage{}, err
	}
	pageSize := q.Limit
	if pageSize == 0 {
		pageSize = 1000
	}
	id, err := cursor.NewID()
	if err != nil {
		return CursorPage{}, err
	}
	if len(d.cursors) >= maxCursors {
		return CursorPage{}, fault("capacity", "%d active cursors reached; close finished traversals", maxCursors)
	}
	now := time.Now().UTC()
	session := &cursorSession{id: id, snapshot: plan.Snapshot, ttl: ttl, expiresAt: now.Add(ttl)}
	if tx != nil {
		session.txn = tx.ID
	}
	page, err := query.Page(r, q, rows, plan, keys, nil, pageSize)
	if err != nil {
		return CursorPage{}, invalid(err)
	}
	session.position = page.Position
	session.done = page.Done
	if page.Done {
		// Whole result fit in the first batch: nothing remains to resume,
		// so no snapshot pin is held and no session is registered.
		d.queries++
		return d.issuePage(session, q, page, plan, pageSize, now)
	}
	d.cursors[id] = session
	d.queries++
	return d.issuePage(session, q, page, plan, pageSize, now)
}

// ContinueCursor verifies a token, re-validates its snapshot against the live
// retention horizon and delivers the next page. Each successful call slides
// the idle deadline and rotates the token.
func (d *DB) ContinueCursor(encoded string) (CursorPage, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.usable(); err != nil {
		return CursorPage{}, err
	}
	token, err := cursor.Decode(d.cursorSecret, encoded)
	if err != nil {
		if err == cursor.ErrForged {
			return CursorPage{}, fault("not_found", "cursor token is not recognized")
		}
		return CursorPage{}, fault("invalid", "%s", err.Error())
	}
	now := time.Now().UTC()
	if token.ExpiresAt <= now.Unix() {
		return CursorPage{}, fault("cursor_expired", "cursor idle deadline passed; restart the traversal with a new cursor")
	}
	q := tokenToRequest(token)
	// Resume against the frozen snapshot, not the current head: for
	// transaction-free cursors the pinned sequence travels as an at read,
	// which also makes a vacuumed snapshot fail here with a clean 410.
	// Transaction cursors keep resolving through their live transaction.
	if q.Transaction == "" {
		snap := token.Snapshot
		q.At = &snap
	}
	r, plan, rows, keys, tx, err := d.snapshotRead(q)
	if err != nil {
		return CursorPage{}, err
	}
	session, known := d.cursors[token.CursorID]
	if !known {
		// Two in-memory-only states look identical here: a process restart
		// (adopt the token again) and an explicit close (refuse it). A
		// tombstone keeps them apart while this instance is alive; after a
		// real restart the map is empty, which is the legitimate resume case.
		if _, closed := d.closedCursors[token.CursorID]; closed {
			return CursorPage{}, fault("not_found", "cursor was explicitly closed")
		}
		if token.Query.Transaction != "" {
			return CursorPage{}, fault("not_found", "owning transaction is no longer active; transaction cursors cannot survive a restart")
		}
		if len(d.cursors) >= maxCursors {
			return CursorPage{}, fault("capacity", "%d active cursors reached; close finished traversals", maxCursors)
		}
		session = &cursorSession{id: token.CursorID, snapshot: token.Snapshot, ttl: time.Duration(token.TTL) * time.Second, expiresAt: now.Add(time.Duration(token.TTL) * time.Second)}
		d.cursors[token.CursorID] = session
	}
	if session.txn != "" {
		if tx == nil || tx.ID != session.txn {
			return CursorPage{}, fault("not_found", "owning transaction is no longer active")
		}
	}
	if session.snapshot != token.Snapshot || plan.Snapshot != token.Snapshot {
		return CursorPage{}, fault("snapshot", "cursor snapshot no longer matches retained state")
	}
	// Ordering guard: the registry position always marks the newest delivered
	// boundary, so replaying an older token after a newer one cannot silently
	// re-read rows. Re-using the exact current token simply serves the next
	// page, which keeps retries after network loss idempotent.
	if len(session.position) > 0 && len(token.Position) > 0 && compareCells(session.position, token.Position) > 0 {
		return CursorPage{}, fault("conflict", "stale cursor token; use the newest token returned by the server")
	}
	position := cellsToValues(token.Position)
	pageSize := token.PageSize
	page, err := query.Page(r, q, rows, plan, keys, position, pageSize)
	if err != nil {
		return CursorPage{}, invalid(err)
	}
	session.position = page.Position
	session.done = page.Done
	if page.Done {
		// A completed traversal no longer pins history and cannot be
		// resumed (the last response carries no token), so drop its
		// session immediately. A tombstone makes any stale-token retry
		// fail cleanly while this instance stays up.
		delete(d.cursors, token.CursorID)
		d.closedCursors[token.CursorID] = time.Unix(token.ExpiresAt, 0).UTC()
	} else {
		session.expiresAt = now.Add(session.ttl)
	}
	d.queries++
	return d.issuePage(session, q, page, plan, pageSize, now)
}

// CloseCursor releases the snapshot pin immediately. An unknown token is a
// 404; an expired one still closes cleanly when the session is present.
func (d *DB) CloseCursor(encoded string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.usable(); err != nil {
		return err
	}
	token, err := cursor.Decode(d.cursorSecret, encoded)
	if err != nil {
		if err == cursor.ErrForged {
			return fault("not_found", "cursor token is not recognized")
		}
		return fault("invalid", "%s", err.Error())
	}
	if _, ok := d.cursors[token.CursorID]; !ok {
		return fault("not_found", "cursor is not active on this instance")
	}
	delete(d.cursors, token.CursorID)
	d.closedCursors[token.CursorID] = time.Unix(token.ExpiresAt, 0).UTC()
	return nil
}

func (d *DB) issuePage(session *cursorSession, q query.Request, page query.PageResult, plan query.Plan, pageSize int, now time.Time) (CursorPage, error) {
	out := CursorPage{
		Done:          page.Done,
		Rows:          page.Rows,
		Plan:          plan,
		Scanned:       page.Scanned,
		Matched:       page.Matched,
		PageSize:      pageSize,
		Snapshot:      session.snapshot,
		ExpiresAt:     session.expiresAt.Format(time.RFC3339Nano),
		RowsDelivered: len(page.Rows),
		TTLSeconds:    int64(session.ttl.Seconds()),
	}
	if !page.Done {
		token := cursor.Token{
			CursorID:  session.id,
			Query:     requestToEnvelope(q),
			Snapshot:  session.snapshot,
			Position:  valuesToCells(page.Position),
			PageSize:  pageSize,
			TTL:       int64(session.ttl.Seconds()),
			ExpiresAt: session.expiresAt.Unix(),
		}
		encoded, err := cursor.Encode(d.cursorSecret, token)
		if err != nil {
			return CursorPage{}, err
		}
		out.Cursor = encoded
	}
	return out, nil
}

// dropTransactionCursors closes every cursor bound to a transaction that is
// committing or rolling back. The token must not become adoptable afterwards
// as if this were a process restart, so a tombstone is recorded as well.
// Called with d.mu held.
func (d *DB) dropTransactionCursors(txnID string) {
	for id, c := range d.cursors {
		if c.txn == txnID {
			delete(d.cursors, id)
			d.closedCursors[id] = c.expiresAt
		}
	}
}

// sweepExpiredCursors removes idle sessions so abandoned clients cannot pin
// history forever, and drops tombstones whose tokens are past their idle
// deadline (such tokens fail on the TTL check anyway), which bounds the
// tombstone set to one TTL window of explicit closes. Called with d.mu held
// from the background sweeper.
func (d *DB) sweepExpiredCursors(now time.Time) int {
	removed := 0
	for id, c := range d.cursors {
		if !c.expiresAt.After(now) {
			delete(d.cursors, id)
			removed++
		}
	}
	for id, deadline := range d.closedCursors {
		if !deadline.After(now) {
			delete(d.closedCursors, id)
		}
	}
	return removed
}

func (d *DB) startCursorSweeper() {
	d.cursorStop = make(chan struct{})
	d.cursorDone = make(chan struct{})
	go func() {
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		defer close(d.cursorDone)
		for {
			select {
			case <-ticker.C:
				d.mu.Lock()
				d.sweepExpiredCursors(time.Now().UTC())
				d.mu.Unlock()
			case <-d.cursorStop:
				return
			}
		}
	}()
}

// cursorHorizon is the oldest snapshot still pinned by an open, unexpired
// cursor. Expired sessions no longer promise resumability and therefore do
// not hold back retention; the sweeper reclaims their memory separately.
func (d *DB) cursorHorizon() (uint64, bool) {
	now := time.Now().UTC()
	oldest := uint64(0)
	found := false
	for _, c := range d.cursors {
		if c.done || !c.expiresAt.After(now) {
			continue
		}
		if !found || c.snapshot < oldest {
			oldest = c.snapshot
			found = true
		}
	}
	return oldest, found
}

func valuesToCells(values []datum.Value) []cursor.PositionCell {
	cells := make([]cursor.PositionCell, len(values))
	for i, v := range values {
		cells[i] = cursor.PositionCell{Kind: v.Kind, Int: v.Int, Text: v.Text, Bool: v.Bool}
		if v.Kind == "" {
			cells[i].Kind = "null"
		}
	}
	return cells
}

func cellsToValues(cells []cursor.PositionCell) []datum.Value {
	values := make([]datum.Value, len(cells))
	for i, c := range cells {
		values[i] = datum.Value{Kind: c.Kind, Int: c.Int, Text: c.Text, Bool: c.Bool}
	}
	return values
}

func compareCells(a []datum.Value, b []cursor.PositionCell) int {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
		cell := datum.Value{Kind: b[i].Kind, Int: b[i].Int, Text: b[i].Text, Bool: b[i].Bool}
		if n := datum.Order(a[i], cell); n != 0 {
			return n
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

func requestToEnvelope(q query.Request) cursor.QueryEnvelope {
	env := cursor.QueryEnvelope{
		Relation:    q.Relation,
		Columns:     append([]string(nil), q.Columns...),
		Order:       make([]cursor.OrderingEnvelope, 0, len(q.Order)),
		At:          q.At,
		Transaction: q.Transaction,
		ForceScan:   q.ForceScan,
	}
	for _, o := range q.Order {
		env.Order = append(env.Order, cursor.OrderingEnvelope{Column: o.Column, Desc: o.Desc})
	}
	for _, p := range q.Where {
		env.Where = append(env.Where, cursor.PredicateEnvelope{
			Column: p.Column,
			Op:     p.Op,
			Value:  valuesToCells([]datum.Value{p.Value})[0],
		})
	}
	return env
}

func tokenToRequest(t cursor.Token) query.Request {
	q := query.Request{
		Relation:    t.Query.Relation,
		Columns:     append([]string(nil), t.Query.Columns...),
		At:          t.Query.At,
		Transaction: t.Query.Transaction,
		ForceScan:   t.Query.ForceScan,
	}
	if len(t.Query.Order) > 0 {
		q.Order = make([]query.Ordering, 0, len(t.Query.Order))
		for _, o := range t.Query.Order {
			q.Order = append(q.Order, query.Ordering{Column: o.Column, Desc: o.Desc})
		}
	}
	if len(t.Query.Where) > 0 {
		q.Where = make([]query.Predicate, 0, len(t.Query.Where))
		for _, p := range t.Query.Where {
			q.Where = append(q.Where, query.Predicate{Column: p.Column, Op: p.Op, Value: cellsToValues([]cursor.PositionCell{p.Value})[0]})
		}
	}
	return q
}
