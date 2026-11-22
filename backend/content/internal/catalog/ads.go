package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var ErrAdRequestConflict = errors.New("ad request already used for another placement")

type Ad struct {
	CampaignID  uuid.UUID `json:"campaign_id"`
	Headline    string    `json:"headline"`
	Destination string    `json:"destination"`
}

func (s *Store) SelectAd(ctx context.Context, viewer, operation uuid.UUID, placement string) (*Ad, error) {
	const query = `SELECT result,ad_id,headline,destination FROM public.content_select_ad($1,$2,$3)`
	var result string
	var campaign uuid.NullUUID
	var headline, destination sql.NullString

	err := s.db.QueryRowContext(ctx, query, viewer, operation, placement).Scan(&result, &campaign, &headline, &destination)
	if err != nil {
		return nil, err
	}

	switch result {
	case "empty":
		return nil, nil
	case "conflict":
		return nil, ErrAdRequestConflict
	case "ad":
		return &Ad{CampaignID: campaign.UUID, Headline: headline.String, Destination: destination.String}, nil
	default:
		return nil, errors.New("unknown ad selection result")
	}
}

type AdCampaignSettings struct {
	Placement   string    `json:"placement"`
	Headline    string    `json:"headline"`
	Destination string    `json:"destination"`
	StartsAt    time.Time `json:"starts_at"`
	EndsAt      time.Time `json:"ends_at"`
	Budget      int64     `json:"delivery_budget"`
	Enabled     *bool     `json:"enabled"`
}

type AdCampaign struct {
	ID uuid.UUID `json:"id"`
	AdCampaignSettings
	Revision            int64 `json:"revision"`
	Deliveries          int64 `json:"deliveries"`
	ReportedImpressions int64 `json:"reported_impressions"`
}

func (s *Store) AdCampaigns(ctx context.Context, after *uuid.UUID, limit int) ([]AdCampaign, error) {
	const query = `SELECT id,placement,headline,destination,starts_at,ends_at,enabled,delivery_budget,deliveries,revision,reported_impressions
		FROM public.content_ad_campaign_list($1,$2) ORDER BY id`
	rows, err := s.db.QueryContext(ctx, query, after, limit)
	if err != nil {
		return nil, fmt.Errorf("list ad campaigns: %w", err)
	}
	defer rows.Close()

	campaigns := make([]AdCampaign, 0, limit)
	for rows.Next() {
		var campaign AdCampaign
		if err := rows.Scan(&campaign.ID, &campaign.Placement, &campaign.Headline, &campaign.Destination,
			&campaign.StartsAt, &campaign.EndsAt, &campaign.Enabled, &campaign.Budget, &campaign.Deliveries,
			&campaign.Revision, &campaign.ReportedImpressions); err != nil {
			return nil, fmt.Errorf("read ad campaign: %w", err)
		}
		campaigns = append(campaigns, campaign)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read ad campaigns: %w", err)
	}
	return campaigns, nil
}

func (s *Store) ReportAdImpression(ctx context.Context, viewer, operation uuid.UUID) (int, error) {
	var status int
	err := s.db.QueryRowContext(ctx, `SELECT public.content_report_ad_impression($1,$2)`, viewer, operation).Scan(&status)
	return status, err
}

func (s *Store) PutAdCampaign(ctx context.Context, actor, campaign uuid.UUID, revision int64, settings AdCampaignSettings) (int, error) {
	const query = `SELECT public.content_ad_campaign_put($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	var status int
	err := s.db.QueryRowContext(ctx, query, actor, campaign, revision, settings.Placement, settings.Headline,
		settings.Destination, settings.StartsAt, settings.EndsAt, settings.Enabled, settings.Budget).Scan(&status)
	return status, err
}

type AdCampaignDay struct {
	Day         string `json:"day"`
	Deliveries  int64  `json:"deliveries"`
	Impressions int64  `json:"reported_impressions"`
}

func (s *Store) AdCampaignDailyReport(ctx context.Context, id uuid.UUID, start, end time.Time) ([]AdCampaignDay, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT * FROM public.content_ad_campaign_daily_report($1,$2::date,$3::date)`, id, start.Format(time.DateOnly), end.Format(time.DateOnly))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]AdCampaignDay, 0, 31)
	for rows.Next() {
		var item AdCampaignDay
		if err := rows.Scan(&item.Day, &item.Deliveries, &item.Impressions); err != nil {
			return nil, err
		}

		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, ErrPostNotFound
	}

	return items, nil
}
