package query

import (
	"lamina/internal/catalog"
	"lamina/internal/datum"
	"sort"
)

// RowLess reproduces the total ordering used by Execute: the explicit
// orderings first (each with its own direction), then the primary key
// ascending as the unique tie breaker, so equal sort values never collide.
func RowLess(r catalog.Relation, order []Ordering, a, b datum.Row) bool {
	for _, o := range order {
		n := datum.Order(a[o.Column], b[o.Column])
		if n != 0 {
			if o.Desc {
				return n > 0
			}
			return n < 0
		}
	}
	return datum.Order(a[r.Primary], b[r.Primary]) < 0
}

// PositionOf returns the lossless keyset position of a sorted row: every
// ordered column followed by the primary key. RowLess decides ordering from
// exactly these values, so the position is a valid resume point even when
// several rows share the same ordering value.
func PositionOf(r catalog.Relation, order []Ordering, row datum.Row) []datum.Value {
	columns := make([]string, 0, len(order)+1)
	for _, o := range order {
		columns = append(columns, o.Column)
	}
	columns = append(columns, r.Primary)
	position := make([]datum.Value, len(columns))
	for i, name := range columns {
		position[i] = row[name]
	}
	return position
}

// PositionRow rebuilds the synthetic row consumed by RowLess from a position.
func PositionRow(r catalog.Relation, order []Ordering, position []datum.Value) datum.Row {
	row := datum.Row{}
	for i, o := range order {
		row[o.Column] = position[i]
	}
	row[r.Primary] = position[len(order)]
	return row
}

// PageResult is one batch of a keyset traversal. Scanned and Matched describe
// the whole snapshot read behind the batch, mirroring the meaning of the same
// fields in Result rather than shrinking to the page window.
type PageResult struct {
	Rows     []datum.Row
	Scanned  int
	Matched  int
	Position []datum.Value
	Done     bool
}

// Page runs the same selection, ordering and projection as Execute but
// resumes strictly after position (nil starts at the beginning) and returns
// at most pageSize rows. Because every page reads the same snapshot, the
// materialized order is identical between calls and the keyset boundary
// cannot skip or duplicate rows.
func Page(r catalog.Relation, q Request, rows map[string]datum.Row, plan Plan, keys []string, position []datum.Value, pageSize int) (PageResult, error) {
	out := PageResult{Rows: []datum.Row{}}
	if plan.Access == "scan" {
		keys = datum.Keys(rows)
	}
	selected := make([]datum.Row, 0)
	for _, key := range keys {
		row, ok := rows[key]
		if !ok {
			continue
		}
		out.Scanned++
		if Matches(row, q.Where) {
			selected = append(selected, row)
		}
	}
	out.Matched = len(selected)
	sort.Slice(selected, func(i, j int) bool {
		return RowLess(r, q.Order, selected[i], selected[j])
	})
	begin := 0
	if position != nil {
		if len(position) != len(q.Order)+1 {
			return out, errInvalidPosition
		}
		boundary := PositionRow(r, q.Order, position)
		begin = sort.Search(len(selected), func(i int) bool {
			return !RowLess(r, q.Order, selected[i], boundary)
		})
		// The boundary row itself was already delivered; resume strictly
		// after it. Stale tokens that no longer match any live row simply
		// continue from the next still-visible position.
		if begin < len(selected) && !RowLess(r, q.Order, boundary, selected[begin]) {
			begin++
		}
	}
	end := len(selected)
	if pageSize > 0 && end-begin > pageSize {
		end = begin + pageSize
		out.Done = false
	} else {
		out.Done = true
	}
	page := selected[begin:end]
	out.Rows = make([]datum.Row, 0, len(page))
	for _, row := range page {
		out.Position = PositionOf(r, q.Order, row)
		if len(q.Columns) == 0 {
			out.Rows = append(out.Rows, datum.Clone(row))
		} else {
			projection := datum.Row{}
			for _, name := range q.Columns {
				projection[name] = row[name]
			}
			out.Rows = append(out.Rows, projection)
		}
	}
	if len(out.Rows) == 0 {
		out.Done = true
		out.Position = nil
	}
	return out, nil
}
