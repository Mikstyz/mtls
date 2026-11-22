package userclient

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

func (c *Client) NextPurge(ctx context.Context) (uuid.UUID, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/internal/media/owner-purges/next", nil)
	if err != nil {
		return uuid.Nil, err
	}
	req.Header.Set("X-Media-Service-Secret", c.secret)
	resp, err := c.http.Do(req)
	if err != nil {
		return uuid.Nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return uuid.Nil, nil
	}
	owners := resp.Header.Values("X-Media-Owner")
	if resp.StatusCode != http.StatusOK || len(owners) != 1 {
		return uuid.Nil, ErrUnavailable
	}
	id, err := uuid.Parse(owners[0])
	if err != nil || id == uuid.Nil {
		return uuid.Nil, ErrInvalid
	}
	return id, nil
}

func (c *Client) FinishPurge(ctx context.Context, owner uuid.UUID) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.base+"/internal/media/owner-purges/"+owner.String()+"/complete", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Media-Service-Secret", c.secret)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return ErrUnavailable
	}
	return nil
}
