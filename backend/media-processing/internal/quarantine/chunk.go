package quarantine

import "errors"

const MaxChunkBytes = 8 << 20

var ErrOffset = errors.New("upload offset does not match")

type Chunk struct {
	Total  int64
	Offset int64
	Length int64
	Digest [32]byte
}
