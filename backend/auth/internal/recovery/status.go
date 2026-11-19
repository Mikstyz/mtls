package recovery

import "errors"

// ErrCompletenessUnproven means local checks passed but do not prove that
// independently preserved changes were not lost before the snapshot.
var ErrCompletenessUnproven = errors.New("snapshot completeness is unproven; keep recovery mode enabled")
