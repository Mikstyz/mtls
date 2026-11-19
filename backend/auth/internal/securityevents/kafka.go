package securityevents

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

type KafkaConfig struct {
	Brokers  []string `toml:"brokers"`
	Topic    string   `toml:"topic"`
	TLS      bool     `toml:"tls"`
	CAFile   string   `toml:"ca_file"`
	Username string   `toml:"username"`
	Password string   `toml:"password"`
}

type Kafka struct {
	client *kgo.Client
	topic  string
}

var topicPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,249}$`)

// OpenKafka validates security settings without making Kafka a startup dependency.
func OpenKafka(cfg KafkaConfig) (*Kafka, error) {
	return openKafka(cfg)
}

func openKafka(cfg KafkaConfig, extra ...kgo.Opt) (*Kafka, error) {
	if len(cfg.Brokers) == 0 {
		if cfg.Topic != "" || cfg.TLS || cfg.CAFile != "" || cfg.Username != "" || cfg.Password != "" {
			return nil, errors.New("kafka brokers are required when kafka settings are present")
		}

		return nil, nil
	}

	if len(cfg.Brokers) > 16 || !topicPattern.MatchString(cfg.Topic) || cfg.Topic == "." || cfg.Topic == ".." {
		return nil, errors.New("invalid kafka brokers or topic")
	}

	if (cfg.Username == "") != (cfg.Password == "") {
		return nil, errors.New("kafka username and password must be configured together")
	}

	if !cfg.TLS && (cfg.CAFile != "" || cfg.Username != "") {
		return nil, errors.New("kafka credentials and CA require TLS")
	}

	for _, broker := range cfg.Brokers {
		local, err := localBroker(broker)

		if err != nil {
			return nil, err
		}

		if !local && (!cfg.TLS || cfg.Username == "") {
			return nil, errors.New("remote kafka requires TLS and SASL credentials")
		}
	}

	var tlsConfig *tls.Config

	if cfg.TLS {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}

		if cfg.CAFile != "" {
			pool, err := loadKafkaCA(cfg.CAFile)

			if err != nil {
				return nil, err
			}

			tlsConfig.RootCAs = pool
		}
	}

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()

		local, err := localBroker(address)

		if err != nil {
			return nil, err
		}

		// Kafka metadata can introduce broker addresses not listed in the config.
		if !local && (!cfg.TLS || cfg.Username == "") {
			return nil, errors.New("remote kafka broker requires TLS and SASL credentials")
		}

		if tlsConfig != nil {
			return (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, network, address)
		}

		return dialer.DialContext(ctx, network, address)
	}

	options := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.Dialer(dial),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.RecordPartitioner(kgo.StickyKeyPartitioner(nil)),
		kgo.AllowIdempotentProduceCancellation(),
		kgo.RecordDeliveryTimeout(15 * time.Second),
		kgo.MaxBufferedRecords(128),
	}

	if cfg.Username != "" {
		options = append(options, kgo.SASL(scram.Auth{User: cfg.Username, Pass: cfg.Password}.AsSha512Mechanism()))
	}

	options = append(options, extra...)

	client, err := kgo.NewClient(options...)

	if err != nil {
		return nil, fmt.Errorf("configure kafka client: %w", err)
	}

	return &Kafka{client: client, topic: cfg.Topic}, nil
}

func (k *Kafka) Publish(ctx context.Context, event Event) error {
	event.CreatedAt = event.CreatedAt.UTC()

	if event.DeletedAt != nil {
		deletedAt := event.DeletedAt.UTC()
		event.DeletedAt = &deletedAt
	}

	payload, err := json.Marshal(struct {
		SchemaVersion int `json:"schema_version"`
		Event
	}{SchemaVersion: 1, Event: event})

	if err != nil {
		return fmt.Errorf("encode security event: %w", err)
	}

	record := &kgo.Record{Topic: k.topic, Key: []byte(event.UserID.String()), Value: payload}

	if err := k.client.ProduceSync(ctx, record).FirstErr(); err != nil {
		return errors.New("kafka security event delivery failed")
	}

	return nil
}

func (k *Kafka) Close() {
	k.client.Close()
}

func localBroker(address string) (bool, error) {
	host, port, err := net.SplitHostPort(address)

	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(host) != host || len(host) > 253 {
		return false, errors.New("invalid kafka broker address")
	}

	portNumber, err := strconv.Atoi(port)

	if err != nil || portNumber < 1 || portNumber > 65535 {
		return false, errors.New("invalid kafka broker port")
	}

	ip := net.ParseIP(host)
	return strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback()), nil
}

func loadKafkaCA(path string) (*x509.CertPool, error) {
	file, err := os.Open(path)

	if err != nil {
		return nil, fmt.Errorf("open kafka CA: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))

	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("cannot read kafka CA")
	}

	pool := x509.NewCertPool()

	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("invalid kafka CA")
	}

	return pool, nil
}
