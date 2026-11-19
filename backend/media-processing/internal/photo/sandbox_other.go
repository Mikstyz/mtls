//go:build !linux

package photo

import (
	"context"
	"errors"
	"time"
)

var ErrProcessorBusy = errors.New("photo processor is busy")

type Processor struct{}

func NewProcessor(string, string, string, string, int, time.Duration) (*Processor, error) {
	return nil, errors.New("photo sandbox requires Linux")
}

func (*Processor) Prepare(context.Context, []byte, int) ([]byte, error) {
	return nil, errors.New("photo sandbox requires Linux")
}

func (*Processor) acquire(context.Context) (func(), error) {
	return nil, errors.New("photo sandbox requires Linux")
}

func (*Processor) prepareLocked(context.Context, []byte, int) ([]byte, error) {
	return nil, errors.New("photo sandbox requires Linux")
}
