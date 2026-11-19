package securityevents

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
)

type JournalConsumer struct {
	kafka      *Kafka
	journal    *Journal
	topic      string
	topicID    uuid.UUID
	partitions []int32
	offsets    map[int32]int64
}

// NewJournalConsumer binds an independent journal to the current topic ID and
// every partition. Positions are kept only in the journal database.
func NewJournalConsumer(ctx context.Context, db *sql.DB, cfg KafkaConfig) (*JournalConsumer, error) {
	discovery, err := OpenKafka(cfg)

	if err != nil {
		return nil, err
	}

	if discovery == nil {
		return nil, errors.New("kafka is required for the security journal")
	}

	topicID, partitions, err := discovery.topicMetadata(ctx)
	discovery.Close()

	if err != nil {
		return nil, err
	}

	journal := NewJournal(db)
	offsets, err := journal.Initialize(ctx, cfg.Topic, topicID, partitions)

	if err != nil {
		return nil, err
	}

	assignment := make(map[int32]kgo.Offset, len(offsets))

	for partition, offset := range offsets {
		assignment[partition] = kgo.NewOffset().At(offset)
	}

	client, err := openKafka(cfg,
		kgo.ConsumePartitions(map[string]map[int32]kgo.Offset{cfg.Topic: assignment}),
		kgo.ConsumeResetOffset(kgo.NoResetOffset()),
		kgo.FetchMaxWait(time.Second),
		kgo.FetchMaxBytes(1<<20),
		kgo.FetchMaxPartitionBytes(1<<20),
	)

	if err != nil {
		return nil, err
	}

	return &JournalConsumer{
		kafka: client, journal: journal, topic: cfg.Topic,
		topicID: topicID, partitions: partitions, offsets: offsets,
	}, nil
}

func (k *Kafka) topicMetadata(ctx context.Context) (uuid.UUID, []int32, error) {
	request := kmsg.NewPtrMetadataRequest()
	request.Topics = []kmsg.MetadataRequestTopic{{Topic: &k.topic}}
	response, err := k.client.Request(ctx, request)

	if err != nil {
		return uuid.Nil, nil, errors.New("cannot retrieve security topic metadata")
	}

	metadata, ok := response.(*kmsg.MetadataResponse)

	if !ok || len(metadata.Topics) != 1 || metadata.Topics[0].ErrorCode != 0 ||
		metadata.Topics[0].Topic == nil || *metadata.Topics[0].Topic != k.topic {
		return uuid.Nil, nil, errors.New("invalid security topic metadata")
	}

	topic := metadata.Topics[0]
	topicID := uuid.UUID(topic.TopicID)

	if topicID == uuid.Nil || len(topic.Partitions) == 0 || len(topic.Partitions) > 64 {
		return uuid.Nil, nil, errors.New("security topic ID or partitions unavailable")
	}

	partitions := make([]int32, 0, len(topic.Partitions))
	seen := make(map[int32]bool, len(topic.Partitions))

	for _, partition := range topic.Partitions {
		if partition.ErrorCode != 0 || partition.Partition < 0 || seen[partition.Partition] {
			return uuid.Nil, nil, errors.New("invalid security topic partition")
		}

		seen[partition.Partition] = true
		partitions = append(partitions, partition.Partition)
	}

	sort.Slice(partitions, func(i, j int) bool { return partitions[i] < partitions[j] })
	return topicID, partitions, nil
}

// Run stops rather than skipping an unknown record, offset gap or topic change.
func (c *JournalConsumer) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		metadataCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		topicID, partitions, err := c.kafka.topicMetadata(metadataCtx)
		cancel()

		if ctx.Err() != nil {
			return nil
		}

		if err != nil {
			return err
		}

		if topicID != c.topicID || len(partitions) != len(c.partitions) {
			return ErrJournalConflict
		}

		for i := range partitions {
			if partitions[i] != c.partitions[i] {
				return ErrJournalConflict
			}
		}

		fetches := c.kafka.client.PollFetches(ctx)

		if ctx.Err() != nil {
			return nil
		}

		if len(fetches.Errors()) != 0 {
			return errors.New("security journal kafka fetch failed")
		}

		var processErr error
		fetches.EachTopic(func(topic kgo.FetchTopic) {
			if processErr != nil {
				return
			}

			if topic.Topic != c.topic || uuid.UUID(topic.TopicID) != c.topicID {
				processErr = ErrJournalConflict
				return
			}

			for _, partition := range topic.Partitions {
				next, ok := c.offsets[partition.Partition]

				if !ok || partition.LogStartOffset < 0 || partition.LogStartOffset > next {
					processErr = ErrJournalGap
					return
				}

				for _, record := range partition.Records {
					writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
					err := c.journal.Archive(writeCtx, c.topic, c.topicID, partition.Partition, record.Offset, record.Key, record.Value)
					cancel()

					if err != nil {
						processErr = fmt.Errorf("archive security event: %w", err)
						return
					}

					if record.Offset >= next {
						next = record.Offset + 1
						c.offsets[partition.Partition] = next
					}
				}
			}
		})

		if processErr != nil {
			return processErr
		}
	}

	return nil
}

func (c *JournalConsumer) Close() {
	c.kafka.Close()
}
