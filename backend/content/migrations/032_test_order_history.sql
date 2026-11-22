CREATE INDEX content_test_orders_buyer_history_idx
    ON content_test_orders (buyer_id, confirmed_at DESC, request_id DESC);

CREATE FUNCTION content_test_receipts(
    buyer UUID, before_time TIMESTAMPTZ, before_request UUID, page_size INTEGER
)
RETURNS TABLE(
    request_id UUID, post_id UUID, revision BIGINT, amount_minor BIGINT, currency TEXT,
    confirmed_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT o.request_id,o.post_id,o.revision,f.amount_minor,f.currency,o.confirmed_at,o.revoked_at
    FROM public.content_test_orders o JOIN public.content_test_offers f USING (post_id, revision)
    WHERE o.buyer_id=buyer
        AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id=buyer)
        AND (
            (before_time IS NULL AND before_request IS NULL)
            OR (before_time IS NOT NULL AND before_request IS NOT NULL
                AND (o.confirmed_at,o.request_id)<(before_time,before_request))
        )
    ORDER BY o.confirmed_at DESC,o.request_id DESC
    LIMIT CASE WHEN page_size BETWEEN 1 AND 41 THEN page_size ELSE 0 END
$$;

REVOKE ALL ON FUNCTION content_test_receipts(UUID,TIMESTAMPTZ,UUID,INTEGER) FROM PUBLIC;
