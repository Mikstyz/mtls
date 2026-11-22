CREATE TABLE content_test_offers (
    post_id UUID NOT NULL REFERENCES content_posts(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL,
    amount_minor BIGINT NOT NULL CHECK (amount_minor BETWEEN 1 AND 999999999),
    currency TEXT NOT NULL CHECK (currency IN ('RUB','USD','EUR')),
    PRIMARY KEY (post_id,revision)
);

CREATE TABLE content_test_orders (
    buyer_id UUID NOT NULL,
    request_id UUID NOT NULL,
    post_id UUID NOT NULL,
    revision BIGINT NOT NULL,
    confirmed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (buyer_id,request_id),
    FOREIGN KEY (post_id,revision) REFERENCES content_test_offers ON DELETE CASCADE
);

CREATE UNIQUE INDEX content_test_order_active_idx ON content_test_orders(post_id,revision,buyer_id)
    WHERE revoked_at IS NULL;

CREATE FUNCTION content_test_entitled(target UUID, edition BIGINT, viewer UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT EXISTS(SELECT 1 FROM public.content_test_orders
        WHERE post_id=target AND revision=edition AND buyer_id=viewer AND revoked_at IS NULL)
$$;

-- The test offer is bound to the exact published edition. Republishing a restored
-- or edited draft requires a new offer and never reuses an old entitlement.
CREATE FUNCTION content_test_offer(target UUID, seller UUID, edition BIGINT, price BIGINT, unit TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || seller::text,0));
    PERFORM 1 FROM public.content_posts p WHERE p.id=target AND p.author_id=seller
        AND p.status='published' AND p.visibility='private' AND p.revision=edition
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=seller)
        FOR SHARE;
    IF NOT FOUND THEN RETURN FALSE; END IF;

    INSERT INTO public.content_test_offers(post_id,revision,amount_minor,currency)
        VALUES(target,edition,price,unit) ON CONFLICT DO NOTHING;
    RETURN EXISTS(SELECT 1 FROM public.content_test_offers WHERE post_id=target AND revision=edition
        AND amount_minor=price AND currency=unit);
END;
$$;

CREATE FUNCTION content_test_purchase(target UUID, buyer UUID, operation UUID, edition BIGINT)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    previous public.content_test_orders%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || buyer::text,0));
    PERFORM 1 FROM public.content_posts p JOIN public.content_test_offers o
        ON o.post_id=p.id AND o.revision=p.revision
        WHERE p.id=target AND p.revision=edition AND p.visibility='private' AND p.status='published'
        AND p.author_id<>buyer AND NOT EXISTS(
            SELECT 1 FROM public.content_author_purges WHERE author_id IN (buyer,p.author_id))
        FOR SHARE OF p;
    IF NOT FOUND THEN RETURN 404; END IF;

    SELECT * INTO previous FROM public.content_test_orders WHERE buyer_id=buyer AND request_id=operation;
    IF FOUND THEN
        IF previous.revoked_at IS NULL AND previous.post_id=target AND previous.revision=edition THEN RETURN 200; END IF;
        RETURN 409;
    END IF;

    INSERT INTO public.content_test_orders(buyer_id,request_id,post_id,revision)
        VALUES(buyer,operation,target,edition) ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN RETURN 409; END IF;
    RETURN 201;
END;
$$;

CREATE FUNCTION content_test_revoke(buyer UUID, operation UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || buyer::text,0));
    UPDATE public.content_test_orders SET revoked_at=COALESCE(revoked_at,clock_timestamp())
        WHERE buyer_id=buyer AND request_id=operation;
    RETURN FOUND;
END;
$$;

CREATE FUNCTION content_purge_test_orders(buyer UUID) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=buyer) THEN
        RAISE EXCEPTION 'missing buyer purge marker';
    END IF;
    DELETE FROM public.content_test_orders WHERE buyer_id=buyer AND request_id IN
        (SELECT request_id FROM public.content_test_orders WHERE buyer_id=buyer ORDER BY request_id LIMIT 500);
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION content_test_entitled(UUID,BIGINT,UUID),content_test_offer(UUID,UUID,BIGINT,BIGINT,TEXT),
    content_test_purchase(UUID,UUID,UUID,BIGINT),content_test_revoke(UUID,UUID),content_purge_test_orders(UUID) FROM PUBLIC;

CREATE FUNCTION content_test_receipt(buyer UUID, operation UUID)
RETURNS TABLE(post_id UUID,revision BIGINT,amount_minor BIGINT,currency TEXT,confirmed_at TIMESTAMPTZ,revoked_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT o.post_id,o.revision,f.amount_minor,f.currency,o.confirmed_at,o.revoked_at
    FROM public.content_test_orders o JOIN public.content_test_offers f USING(post_id,revision)
    WHERE o.buyer_id=buyer AND o.request_id=operation
$$;
REVOKE ALL ON FUNCTION content_test_receipt(UUID,UUID) FROM PUBLIC;
