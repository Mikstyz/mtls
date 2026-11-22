use std::sync::Arc;

use serde::Deserialize;
use tokio::sync::Semaphore;
use tokio_postgres::Client;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Document {
    pub(crate) version: i64,
    pub(crate) text: String,
    pub(crate) deleted: bool,
}

#[derive(Debug)]
pub(crate) struct Unavailable;

pub(crate) enum UpdateOutcome {
    Applied,
    Conflict,
    Unavailable,
}

pub(crate) struct Index {
    db: Client,
    slots: Arc<Semaphore>,
}

pub(crate) struct RankPosition {
    pub(crate) id: Uuid,
    pub(crate) rank: f32,
    pub(crate) snapshot: i64,
}

impl Index {
    pub(crate) fn new(db: Client, max_requests: usize) -> Self {
        Self {
            db,
            slots: Arc::new(Semaphore::new(max_requests)),
        }
    }

    // The spawned task retains its permit until the database request completes,
    // even when the HTTP client disconnects.
    pub(crate) async fn update(
        self: &Arc<Self>,
        kind: String,
        id: Uuid,
        document: Document,
    ) -> Result<UpdateOutcome, Unavailable> {
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Unavailable)?;
        let index = self.clone();

        tokio::spawn(async move {
            let _permit = permit;
            index.update_in_database(kind, id, document).await
        })
        .await
        .map_err(|_| Unavailable)?
        .map_err(|_| Unavailable)
    }

    async fn update_in_database(
        &self,
        kind: String,
        id: Uuid,
        document: Document,
    ) -> Result<UpdateOutcome, tokio_postgres::Error> {
        let updated = self.db.query_opt(
            "INSERT INTO search_documents (kind, id, source_version, deleted, search_text)
             SELECT $1, $2, $3, $4, $5
             WHERE EXISTS (SELECT 1 FROM search_version_floors WHERE kind=$1 AND min_version < $3)
             ON CONFLICT (kind, id) DO UPDATE
             SET source_version = EXCLUDED.source_version, deleted = EXCLUDED.deleted, search_text = EXCLUDED.search_text
             WHERE search_documents.source_version < EXCLUDED.source_version
                OR (search_documents.source_version = EXCLUDED.source_version
                    AND search_documents.deleted = EXCLUDED.deleted
                    AND search_documents.search_text = EXCLUDED.search_text)
             RETURNING id",
            &[&kind, &id, &document.version, &document.deleted, &document.text],
        ).await?;

        if updated.is_some() {
            return Ok(UpdateOutcome::Applied);
        }

        let floor = self
            .db
            .query_opt(
                "SELECT min_version FROM search_version_floors WHERE kind = $1",
                &[&kind],
            )
            .await?;

        match floor {
            Some(row) if document.version <= row.get::<_, i64>(0) => {
                return Ok(UpdateOutcome::Applied)
            }
            Some(_) => {}
            None => return Ok(UpdateOutcome::Unavailable),
        }

        let current = self
            .db
            .query_opt(
                "SELECT source_version FROM search_documents WHERE kind = $1 AND id = $2",
                &[&kind, &id],
            )
            .await?;

        match current {
            Some(row) if row.get::<_, i64>(0) > document.version => Ok(UpdateOutcome::Applied),
            Some(_) => Ok(UpdateOutcome::Conflict),
            None => Ok(UpdateOutcome::Unavailable),
        }
    }

    pub(crate) async fn search(
        self: &Arc<Self>,
        kind: String,
        query: String,
        limit: i64,
    ) -> Result<Vec<Uuid>, Unavailable> {
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Unavailable)?;
        let index = self.clone();

        let rows = tokio::spawn(async move {
            let _permit = permit;
            index
                .db
                .query(
                    "SELECT id FROM search_documents
                 WHERE kind = $1 AND NOT deleted AND document @@ plainto_tsquery('simple', $2)
                 ORDER BY ts_rank_cd(document, plainto_tsquery('simple', $2)) DESC, id
                 LIMIT $3",
                    &[&kind, &query, &limit],
                )
                .await
        })
        .await
        .map_err(|_| Unavailable)?
        .map_err(|_| Unavailable)?;

        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }

    pub(crate) async fn search_page(
        self: &Arc<Self>,
        kind: String,
        query: String,
        prefix: String,
        limit: i64,
        before: Option<RankPosition>,
    ) -> Result<Vec<RankPosition>, Unavailable> {
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Unavailable)?;
        let index = self.clone();
        let (snapshot, rank, id) = match before {
            Some(before) => (Some(before.snapshot), Some(before.rank), Some(before.id)),
            None => (None, None, None),
        };

        let rows = tokio::spawn(async move {
            let _permit = permit;
            index.db.query(
                "WITH fence AS (
                     SELECT COALESCE($4::bigint, (SELECT max(source_version) FROM search_documents WHERE kind=$1), 0) AS version
                 ),
                 terms AS (
                     SELECT CASE WHEN $7::text = '' THEN plainto_tsquery('simple', $2)
                            ELSE plainto_tsquery('simple', $2) && to_tsquery('simple', $7 || ':*') END AS query
                 ),
                 matches AS (
                     SELECT d.id, ts_rank_cd(d.document, terms.query) AS rank, fence.version
                     FROM search_documents d CROSS JOIN fence CROSS JOIN terms
                     WHERE d.kind=$1 AND NOT d.deleted AND d.source_version<=fence.version
                         AND d.document @@ terms.query
                 )
                 SELECT id, rank, version FROM matches
                 WHERE $5::real IS NULL OR rank < $5 OR (rank=$5 AND id>$6::uuid)
                 ORDER BY rank DESC, id
                 LIMIT $3",
                &[&kind, &query, &limit, &snapshot, &rank, &id, &prefix],
            ).await
        }).await.map_err(|_| Unavailable)?.map_err(|_| Unavailable)?;

        rows.into_iter()
            .map(|row| {
                Ok(RankPosition {
                    id: row.try_get(0).map_err(|_| Unavailable)?,
                    rank: row.try_get(1).map_err(|_| Unavailable)?,
                    snapshot: row.try_get(2).map_err(|_| Unavailable)?,
                })
            })
            .collect()
    }
}
