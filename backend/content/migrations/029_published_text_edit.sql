ALTER TABLE content_posts ADD COLUMN published_edition BIGINT
    CHECK(published_edition>0 AND published_edition<=revision);

CREATE FUNCTION content_edit_post(owner UUID,target UUID,expected BIGINT,new_title TEXT,new_description TEXT,wanted_status TEXT)
RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    item public.content_posts%ROWTYPE;
BEGIN
    IF expected IS NULL OR expected NOT BETWEEN 1 AND 9223372036854775806
        OR wanted_status IS NULL OR wanted_status NOT IN ('draft','published')
        OR new_title IS NULL OR char_length(new_title)>200
        OR new_description IS NULL OR char_length(new_description)>4096
        OR (wanted_status='published' AND btrim(new_title)='')
    THEN RETURN -2; END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || owner::text,0));
    SELECT * INTO item FROM public.content_posts p WHERE p.id=target AND p.author_id=owner
        AND p.status=wanted_status AND (wanted_status='published' OR p.visibility='private')
        AND p.hidden_by_case IS NULL
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=owner)
    FOR UPDATE;
    IF NOT FOUND THEN RETURN -1; END IF;
    IF item.revision=expected+1 AND item.title=new_title AND item.description=new_description THEN
        RETURN item.revision;
    END IF;
    IF item.revision<>expected THEN RETURN 0; END IF;
    IF item.title=new_title AND item.description=new_description THEN RETURN item.revision; END IF;

    UPDATE public.content_posts SET title=new_title,description=new_description,revision=revision+1,
        published_edition=CASE WHEN wanted_status='published' THEN COALESCE(item.published_edition,item.revision) ELSE NULL END
    WHERE id=target RETURNING revision INTO item.revision;
    RETURN item.revision;
END;
$$;
REVOKE ALL ON FUNCTION content_edit_post(UUID,UUID,BIGINT,TEXT,TEXT,TEXT) FROM PUBLIC;

CREATE OR REPLACE FUNCTION content_guard_draft_edit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'invalid post revision';
    END IF;

    IF OLD.status = 'draft' AND OLD.visibility = 'private'
        AND NEW.status = 'draft' AND NEW.visibility = 'private'
        AND NEW.published_at IS NOT DISTINCT FROM OLD.published_at THEN
        RETURN NEW;
    END IF;

    IF OLD.status='published' AND NEW.status='published' AND NEW.visibility=OLD.visibility
        AND NEW.published_at IS NOT DISTINCT FROM OLD.published_at
        AND NEW.published_edition=COALESCE(OLD.published_edition,OLD.revision) THEN
        RETURN NEW;
    END IF;

    IF NEW.title IS DISTINCT FROM OLD.title OR NEW.description IS DISTINCT FROM OLD.description THEN
        RAISE EXCEPTION 'invalid post state change';
    END IF;

    IF OLD.status = 'draft' AND OLD.visibility = 'private'
        AND NEW.status = 'published' AND NEW.visibility IN ('private', 'public') THEN
        RETURN NEW;
    END IF;

    IF OLD.status IN ('draft', 'published') AND NEW.status = 'removed'
        AND NEW.author_removed_at IS NOT NULL AND NEW.visibility = OLD.visibility
        AND NEW.published_at IS NOT DISTINCT FROM OLD.published_at THEN
        RETURN NEW;
    END IF;

    IF OLD.status = 'removed' AND OLD.author_removed_at IS NOT NULL
        AND NEW.status = 'draft' AND NEW.visibility = 'private'
        AND NEW.author_removed_at IS NULL AND NEW.published_at IS NULL THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid post state change';
END;
$$;

CREATE OR REPLACE FUNCTION content_publish_post(
    draft_author UUID, draft_id UUID, expected_revision BIGINT, target_visibility TEXT
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    current_post public.content_posts%ROWTYPE;
BEGIN
    IF expected_revision IS NULL OR expected_revision NOT BETWEEN 1 AND 9223372036854775806
        OR target_visibility IS NULL OR target_visibility NOT IN ('private', 'public') THEN
        RAISE EXCEPTION 'invalid draft revision' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || draft_author::text, 0));
    SELECT * INTO current_post FROM public.content_posts
    WHERE id = draft_id AND author_id = draft_author AND ((status = 'draft' AND visibility = 'private') OR status = 'published')
        AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id = draft_author)
    FOR UPDATE;
    IF NOT FOUND THEN RETURN -1; END IF;

    IF current_post.status = 'published' AND current_post.revision = expected_revision + 1
        AND current_post.visibility = target_visibility THEN
        RETURN current_post.revision;
    END IF;

    IF current_post.status <> 'draft' OR current_post.revision <> expected_revision THEN
        RETURN 0;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM public.content_post_media WHERE post_id = draft_id)
        OR btrim(current_post.title) = '' THEN
        RETURN -2;
    END IF;

    UPDATE public.content_posts SET status = 'published', visibility = target_visibility,
        published_at = clock_timestamp(), published_edition=NULL, revision = revision + 1
        WHERE id = draft_id RETURNING revision INTO current_post.revision;
    RETURN current_post.revision;
END;
$$;

CREATE OR REPLACE FUNCTION content_test_offer(target UUID, seller UUID, edition BIGINT, price BIGINT, unit TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || seller::text,0));
    PERFORM 1 FROM public.content_posts p WHERE p.id=target AND p.author_id=seller
        AND p.status='published' AND p.hidden_by_case IS NULL AND p.visibility='private' AND COALESCE(p.published_edition,p.revision)=edition
        AND NOT EXISTS(SELECT 1 FROM public.content_author_purges WHERE author_id=seller)
        FOR SHARE;
    IF NOT FOUND THEN RETURN FALSE; END IF;

    INSERT INTO public.content_test_offers(post_id,revision,amount_minor,currency)
        VALUES(target,edition,price,unit) ON CONFLICT DO NOTHING;
    RETURN EXISTS(SELECT 1 FROM public.content_test_offers WHERE post_id=target AND revision=edition
        AND amount_minor=price AND currency=unit);
END;
$$;

CREATE OR REPLACE FUNCTION content_test_purchase(target UUID, buyer UUID, operation UUID, edition BIGINT)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    previous public.content_test_orders%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || buyer::text,0));
    PERFORM 1 FROM public.content_posts p JOIN public.content_test_offers o
        ON o.post_id=p.id AND o.revision=COALESCE(p.published_edition,p.revision)
        WHERE p.id=target AND COALESCE(p.published_edition,p.revision)=edition AND p.visibility='private' AND p.status='published' AND p.hidden_by_case IS NULL
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

CREATE OR REPLACE FUNCTION content_test_entitled(target UUID, edition BIGINT, viewer UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT EXISTS(SELECT 1 FROM public.content_test_orders o JOIN public.content_posts p ON p.id=o.post_id
        WHERE p.id=target AND p.revision=edition AND p.status='published' AND p.hidden_by_case IS NULL
        AND o.revision=COALESCE(p.published_edition,p.revision) AND o.buyer_id=viewer AND o.revoked_at IS NULL)
$$;
