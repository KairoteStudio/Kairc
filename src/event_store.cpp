#include "kairc/event_store.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <string>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>

namespace kairc {

namespace {

class Statement {
  public:
    Statement(sqlite3 *database, const char *sql) : database_(database) {
        if (sqlite3_prepare_v2(database, sql, -1, &statement_, nullptr) != SQLITE_OK) {
            throw Error(std::string("SQLite prepare failed: ") + sqlite3_errmsg(database));
        }
    }

    ~Statement() {
        sqlite3_finalize(statement_);
    }

    Statement(const Statement &) = delete;
    Statement &operator=(const Statement &) = delete;

    sqlite3_stmt *get() const noexcept {
        return statement_;
    }

    void bind_blob(int index, std::span<const Byte> value) {
        if (sqlite3_bind_blob(statement_, index, value.data(), static_cast<int>(value.size()),
                              SQLITE_TRANSIENT) != SQLITE_OK) {
            throw Error(std::string("SQLite bind failed: ") + sqlite3_errmsg(database_));
        }
    }

    void bind_int64(int index, std::uint64_t value) {
        if (value > static_cast<std::uint64_t>(std::numeric_limits<sqlite3_int64>::max())) {
            throw Error("integer does not fit in SQLite's signed range");
        }
        if (sqlite3_bind_int64(statement_, index, static_cast<sqlite3_int64>(value)) != SQLITE_OK) {
            throw Error(std::string("SQLite bind failed: ") + sqlite3_errmsg(database_));
        }
    }

    void bind_int(int index, int value) {
        if (sqlite3_bind_int(statement_, index, value) != SQLITE_OK) {
            throw Error(std::string("SQLite bind failed: ") + sqlite3_errmsg(database_));
        }
    }

    int step() {
        const int result = sqlite3_step(statement_);
        if (result != SQLITE_ROW && result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
            throw Error(std::string("SQLite step failed: ") + sqlite3_errmsg(database_));
        }
        return result;
    }

  private:
    sqlite3 *database_ = nullptr;
    sqlite3_stmt *statement_ = nullptr;
};

void execute(sqlite3 *database, const char *sql) {
    char *message = nullptr;
    if (sqlite3_exec(database, sql, nullptr, nullptr, &message) != SQLITE_OK) {
        std::string detail = message == nullptr ? sqlite3_errmsg(database) : message;
        sqlite3_free(message);
        throw Error("SQLite operation failed: " + detail);
    }
}

std::uint64_t query_uint64(sqlite3 *database, const char *sql, std::string_view label) {
    Statement statement(database, sql);
    if (statement.step() != SQLITE_ROW) {
        throw Error("SQLite did not return " + std::string(label));
    }
    const sqlite3_int64 value = sqlite3_column_int64(statement.get(), 0);
    if (value < 0) {
        throw Error("SQLite returned a negative " + std::string(label));
    }
    return static_cast<std::uint64_t>(value);
}

std::uint64_t existing_file_size(const std::filesystem::path &path) {
    std::error_code error;
    const std::uintmax_t size = std::filesystem::file_size(path, error);
    if (error) {
        return 0;
    }
    if (size > std::numeric_limits<std::uint64_t>::max()) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return static_cast<std::uint64_t>(size);
}

Hash column_hash(sqlite3_stmt *statement, int column) {
    const auto *data = static_cast<const Byte *>(sqlite3_column_blob(statement, column));
    const int size = sqlite3_column_bytes(statement, column);
    if (data == nullptr || size != static_cast<int>(Hash{}.size())) {
        throw Error("SQLite contains a malformed event hash");
    }
    return fixed_bytes<32>(std::span<const Byte>(data, static_cast<std::size_t>(size)),
                           "stored hash");
}

Bytes column_bytes(sqlite3_stmt *statement, int column) {
    const auto *data = static_cast<const Byte *>(sqlite3_column_blob(statement, column));
    const int size = sqlite3_column_bytes(statement, column);
    if (size < 0 || (data == nullptr && size != 0)) {
        throw Error("SQLite contains a malformed byte string");
    }
    if (size == 0) {
        return {};
    }
    return Bytes(data, data + size);
}

void prepare_database_file(const std::filesystem::path &path) {
    if (path == ":memory:") {
        return;
    }
    const int descriptor = ::open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        throw Error("could not create private event-store file: " +
                    std::error_code(errno, std::generic_category()).message());
    }
    const int permission_result = ::fchmod(descriptor, S_IRUSR | S_IWUSR);
    const int permission_error = errno;
    ::close(descriptor);
    if (permission_result < 0) {
        throw Error("could not restrict event-store permissions: " +
                    std::error_code(permission_error, std::generic_category()).message());
    }
}

} // namespace

EventStore::EventStore(const std::filesystem::path &path, Hash network, EventStoreOptions options)
    : network_(network), path_(path), options_(options) {
    constexpr std::uint64_t minimum_store_bytes = 16ULL * 1024ULL * 1024ULL;
    constexpr std::uint64_t maximum_store_bytes = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
    if (options_.max_bytes < minimum_store_bytes || options_.max_bytes > maximum_store_bytes) {
        throw Error("event-store max_bytes must be between 16 MiB and 1 TiB");
    }
    if (options_.max_events_per_epoch == 0 || options_.max_events_per_epoch > 10'000'000) {
        throw Error("event-store max_events_per_epoch must be between 1 and 10000000");
    }
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }
    prepare_database_file(path);
    if (sqlite3_open_v2(path.string().c_str(), &database_,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                        nullptr) != SQLITE_OK) {
        const std::string detail =
            database_ == nullptr ? "unknown error" : sqlite3_errmsg(database_);
        if (database_ != nullptr) {
            sqlite3_close(database_);
            database_ = nullptr;
        }
        throw Error("could not open event store: " + detail);
    }
    try {
        if (path != ":memory:") {
            std::error_code permission_error;
            std::filesystem::permissions(
                path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace, permission_error);
            if (permission_error) {
                throw Error("could not restrict event-store permissions: " +
                            permission_error.message());
            }
        }
        sqlite3_busy_timeout(database_, 5000);
        execute(database_, "PRAGMA foreign_keys = ON");
        // This takes effect immediately for a new database. Existing databases
        // keep their current auto-vacuum mode and still benefit from page reuse.
        execute(database_, "PRAGMA auto_vacuum = INCREMENTAL");
        execute(database_, "PRAGMA journal_mode = WAL");
        execute(database_, "PRAGMA wal_autocheckpoint = 256");

        const std::uint64_t page_size = query_uint64(database_, "PRAGMA page_size", "page size");
        const std::uint64_t wal_budget =
            std::min<std::uint64_t>(16ULL * 1024ULL * 1024ULL, options_.max_bytes / 8ULL);
        const std::uint64_t database_budget = options_.max_bytes - wal_budget;
        const std::uint64_t maximum_pages = std::max<std::uint64_t>(1, database_budget / page_size);
        const std::string max_page_count =
            "PRAGMA max_page_count = " + std::to_string(maximum_pages);
        execute(database_, max_page_count.c_str());
        const std::string journal_size_limit =
            "PRAGMA journal_size_limit = " + std::to_string(wal_budget);
        execute(database_, journal_size_limit.c_str());

        execute(database_, "CREATE TABLE IF NOT EXISTS metadata ("
                           "key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL) WITHOUT ROWID");
        {
            Statement lookup(database_, "SELECT value FROM metadata WHERE key = 'network'");
            if (lookup.step() == SQLITE_ROW) {
                const Bytes stored = column_bytes(lookup.get(), 0);
                if (stored.size() != network_.size() ||
                    !std::equal(stored.begin(), stored.end(), network_.begin())) {
                    throw Error("event store belongs to another network or PoW difficulty");
                }
            } else {
                Statement bind(database_, "INSERT INTO metadata(key, value) VALUES('network', ?1)");
                bind.bind_blob(1, network_);
                bind.step();
            }
        }
        execute(database_, "CREATE TABLE IF NOT EXISTS events ("
                           "id BLOB PRIMARY KEY NOT NULL,"
                           "epoch INTEGER NOT NULL,"
                           "timestamp_ms INTEGER NOT NULL,"
                           "channel BLOB NOT NULL,"
                           "raw BLOB NOT NULL) WITHOUT ROWID");
        execute(database_, "CREATE INDEX IF NOT EXISTS events_time ON events(timestamp_ms DESC)");
        execute(database_, "CREATE INDEX IF NOT EXISTS events_epoch ON events(epoch)");
        execute(database_, "CREATE INDEX IF NOT EXISTS events_channel_time "
                           "ON events(channel, timestamp_ms DESC)");
        execute(database_, "CREATE TABLE IF NOT EXISTS edges ("
                           "parent BLOB NOT NULL REFERENCES events(id) ON DELETE CASCADE,"
                           "child BLOB NOT NULL REFERENCES events(id) ON DELETE CASCADE,"
                           "PRIMARY KEY(parent, child)) WITHOUT ROWID");
        execute(
            database_,
            "CREATE TABLE IF NOT EXISTS tips ("
            "epoch INTEGER NOT NULL,"
            "id BLOB PRIMARY KEY NOT NULL REFERENCES events(id) ON DELETE CASCADE) WITHOUT ROWID");
        execute(database_, "CREATE TABLE IF NOT EXISTS event_layers ("
                           "id BLOB PRIMARY KEY NOT NULL REFERENCES events(id) ON DELETE CASCADE,"
                           "layer INTEGER NOT NULL CHECK(layer >= 1)) WITHOUT ROWID");
        execute(database_, "CREATE TABLE IF NOT EXISTS peer_records ("
                           "identity BLOB PRIMARY KEY NOT NULL,"
                           "sequence INTEGER NOT NULL CHECK(sequence > 0),"
                           "record_id BLOB NOT NULL,"
                           "expires_at INTEGER NOT NULL CHECK(expires_at > 0),"
                           "watermark_until INTEGER NOT NULL CHECK(watermark_until > 0),"
                           "ever_verified INTEGER NOT NULL CHECK(ever_verified IN (0, 1)),"
                           "trusted_priority INTEGER NOT NULL "
                           "CHECK(trusted_priority IN (0, 1)),"
                           "raw BLOB NOT NULL) WITHOUT ROWID");
        {
            bool has_watermark = false;
            bool has_ever_verified = false;
            bool has_trusted_priority = false;
            Statement columns(database_, "PRAGMA table_info(peer_records)");
            while (columns.step() == SQLITE_ROW) {
                const auto *name = sqlite3_column_text(columns.get(), 1);
                if (name == nullptr) {
                    continue;
                }
                const std::string_view column(reinterpret_cast<const char *>(name));
                if (column == "watermark_until") {
                    has_watermark = true;
                } else if (column == "ever_verified") {
                    has_ever_verified = true;
                } else if (column == "trusted_priority") {
                    has_trusted_priority = true;
                }
            }
            if (!has_watermark) {
                execute(database_, "ALTER TABLE peer_records ADD COLUMN watermark_until "
                                   "INTEGER NOT NULL DEFAULT 0");
                // Existing development databases did not separate record
                // usability from rollback protection.  Give migrated rows a
                // full observation horizon so restart cannot revive an older
                // still-valid withdrawal.
                execute(database_, "UPDATE peer_records SET watermark_until = "
                                   "MAX(expires_at, CAST(strftime('%s','now') AS INTEGER) + 7500) "
                                   "WHERE watermark_until = 0");
            }
            if (!has_ever_verified) {
                execute(database_, "ALTER TABLE peer_records ADD COLUMN ever_verified "
                                   "INTEGER NOT NULL DEFAULT 0");
            }
            if (!has_trusted_priority) {
                execute(database_, "ALTER TABLE peer_records ADD COLUMN trusted_priority "
                                   "INTEGER NOT NULL DEFAULT 0 "
                                   "CHECK(trusted_priority IN (0, 1))");
            }
        }
        execute(database_, "CREATE INDEX IF NOT EXISTS peer_records_expiry "
                           "ON peer_records(expires_at)");
        execute(database_, "CREATE INDEX IF NOT EXISTS peer_records_watermark "
                           "ON peer_records(watermark_until)");
        execute(database_, "CREATE INDEX IF NOT EXISTS peer_records_trust "
                           "ON peer_records(trusted_priority)");
        execute(database_, "CREATE TABLE IF NOT EXISTS local_peer_record_sequences ("
                           "identity BLOB PRIMARY KEY NOT NULL,"
                           "sequence INTEGER NOT NULL CHECK(sequence > 0)) WITHOUT ROWID");

        // Schema migration for databases created by 0.2.0. Parent closure makes
        // the longest-path layer deterministic, independent of arrival order.
        execute(database_, "INSERT OR IGNORE INTO event_layers(id, layer) "
                           "SELECT e.id, 1 FROM events e "
                           "WHERE NOT EXISTS (SELECT 1 FROM edges x WHERE x.child = e.id)");
        for (;;) {
            execute(database_,
                    "INSERT OR IGNORE INTO event_layers(id, layer) "
                    "SELECT e.id, MAX(parent_layer.layer) + 1 "
                    "FROM events e "
                    "JOIN edges x ON x.child = e.id "
                    "JOIN event_layers parent_layer ON parent_layer.id = x.parent "
                    "WHERE NOT EXISTS (SELECT 1 FROM event_layers own WHERE own.id = e.id) "
                    "GROUP BY e.id "
                    "HAVING COUNT(*) = (SELECT COUNT(*) FROM edges all_edges "
                    "                   WHERE all_edges.child = e.id)");
            if (sqlite3_changes(database_) == 0) {
                break;
            }
        }
        if (query_uint64(database_,
                         "SELECT COUNT(*) FROM events e WHERE NOT EXISTS "
                         "(SELECT 1 FROM event_layers l WHERE l.id = e.id)",
                         "unlayered event count") != 0) {
            throw Error("event store contains a cyclic or incomplete parent graph");
        }
    } catch (...) {
        sqlite3_close(database_);
        database_ = nullptr;
        throw;
    }
}

EventStore::~EventStore() {
    if (database_ != nullptr) {
        sqlite3_close(database_);
    }
}

bool EventStore::contains(const Hash &id) const {
    Statement statement(database_, "SELECT 1 FROM events WHERE id = ?1");
    statement.bind_blob(1, id);
    return statement.step() == SQLITE_ROW;
}

std::optional<Event> EventStore::load(const Hash &id) const {
    Statement statement(database_, "SELECT raw FROM events WHERE id = ?1");
    statement.bind_blob(1, id);
    if (statement.step() != SQLITE_ROW) {
        return std::nullopt;
    }
    return Event::deserialize(column_bytes(statement.get(), 0));
}

std::vector<Hash> EventStore::missing_parents(const Event &event) const {
    std::vector<Hash> missing;
    const Hash root = epoch_root(network_, event.epoch());
    Statement statement(database_, "SELECT epoch FROM events WHERE id = ?1");
    for (const Hash &parent : event.parents) {
        if (parent == root) {
            continue;
        }
        sqlite3_reset(statement.get());
        sqlite3_clear_bindings(statement.get());
        statement.bind_blob(1, parent);
        if (statement.step() != SQLITE_ROW) {
            missing.push_back(parent);
            continue;
        }
        const auto parent_epoch =
            static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
        if (parent_epoch != event.epoch()) {
            throw Error("event references a parent from another rotation epoch");
        }
    }
    return missing;
}

InsertStatus EventStore::insert(const Event &event) {
    if (event.network != network_ || event.id != event.calculate_id()) {
        throw Error("event store refused an event with the wrong network or content ID");
    }
    if (contains(event.id)) {
        return InsertStatus::duplicate;
    }
    if (!missing_parents(event).empty()) {
        return InsertStatus::missing_parent;
    }

    {
        Statement count(database_, "SELECT COUNT(*) FROM events WHERE epoch = ?1");
        count.bind_int64(1, event.epoch());
        if (count.step() != SQLITE_ROW) {
            throw Error("could not count events in the rotation epoch");
        }
        const auto epoch_events = static_cast<std::uint64_t>(sqlite3_column_int64(count.get(), 0));
        if (epoch_events >= options_.max_events_per_epoch) {
            return InsertStatus::quota_exceeded;
        }
    }

    const Bytes raw = event.serialize();
    constexpr std::uint64_t per_event_storage_headroom = 64ULL * 1024ULL;
    const std::uint64_t current_storage = storage_bytes();
    const std::uint64_t requested =
        static_cast<std::uint64_t>(raw.size()) + per_event_storage_headroom;
    if (current_storage >= options_.max_bytes || requested > options_.max_bytes - current_storage) {
        return InsertStatus::quota_exceeded;
    }
    execute(database_, "BEGIN IMMEDIATE");
    try {
        std::uint64_t layer = 1;
        const Hash root = epoch_root(network_, event.epoch());
        Statement find_parent_layer(database_, "SELECT layer FROM event_layers WHERE id = ?1");
        for (const Hash &parent : event.parents) {
            if (parent == root) {
                continue;
            }
            sqlite3_reset(find_parent_layer.get());
            sqlite3_clear_bindings(find_parent_layer.get());
            find_parent_layer.bind_blob(1, parent);
            if (find_parent_layer.step() != SQLITE_ROW) {
                throw Error("event parent has no canonical layer");
            }
            const sqlite3_int64 parent_layer = sqlite3_column_int64(find_parent_layer.get(), 0);
            if (parent_layer < 1 || parent_layer == std::numeric_limits<sqlite3_int64>::max()) {
                throw Error("event parent has an invalid canonical layer");
            }
            layer = std::max(layer, static_cast<std::uint64_t>(parent_layer) + 1);
        }

        Statement insert_event(
            database_,
            "INSERT INTO events(id, epoch, timestamp_ms, channel, raw) VALUES(?1, ?2, ?3, ?4, ?5)");
        insert_event.bind_blob(1, event.id);
        insert_event.bind_int64(2, event.epoch());
        insert_event.bind_int64(3, event.timestamp_ms);
        insert_event.bind_blob(4, event.channel);
        insert_event.bind_blob(5, raw);
        const int result = insert_event.step();
        if (result == SQLITE_CONSTRAINT) {
            execute(database_, "ROLLBACK");
            return InsertStatus::duplicate;
        }

        for (const Hash &parent : event.parents) {
            if (parent == root) {
                continue;
            }
            Statement edge(database_, "INSERT INTO edges(parent, child) VALUES(?1, ?2)");
            edge.bind_blob(1, parent);
            edge.bind_blob(2, event.id);
            edge.step();

            Statement remove_tip(database_, "DELETE FROM tips WHERE id = ?1");
            remove_tip.bind_blob(1, parent);
            remove_tip.step();
        }

        Statement add_tip(database_, "INSERT INTO tips(epoch, id) VALUES(?1, ?2)");
        add_tip.bind_int64(1, event.epoch());
        add_tip.bind_blob(2, event.id);
        add_tip.step();

        Statement add_layer(database_, "INSERT INTO event_layers(id, layer) VALUES(?1, ?2)");
        add_layer.bind_blob(1, event.id);
        add_layer.bind_int64(2, layer);
        add_layer.step();
        execute(database_, "COMMIT");
        return InsertStatus::inserted;
    } catch (...) {
        sqlite3_exec(database_, "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

std::vector<Hash> EventStore::tips(std::uint64_t epoch, std::size_t limit) const {
    limit = std::min<std::size_t>(limit, kMaxEventParents);
    Statement statement(database_, "SELECT id FROM tips WHERE epoch = ?1 ORDER BY id LIMIT ?2");
    statement.bind_int64(1, epoch);
    statement.bind_int(2, static_cast<int>(limit));
    std::vector<Hash> output;
    while (statement.step() == SQLITE_ROW) {
        output.push_back(column_hash(statement.get(), 0));
    }
    return output;
}

std::vector<Hash> EventStore::recent_ids(std::size_t limit) const {
    limit = std::min<std::size_t>(limit, 1024);
    Statement statement(database_, "SELECT id FROM events ORDER BY timestamp_ms DESC LIMIT ?1");
    statement.bind_int(1, static_cast<int>(limit));
    std::vector<Hash> output;
    while (statement.step() == SQLITE_ROW) {
        output.push_back(column_hash(statement.get(), 0));
    }
    return output;
}

std::vector<Event> EventStore::recent_for_channel(const Hash &channel, std::size_t limit) const {
    limit = std::min<std::size_t>(limit, 512);
    Statement statement(database_, "SELECT e.raw FROM events e "
                                   "JOIN event_layers l ON l.id = e.id "
                                   "WHERE e.channel = ?1 "
                                   "ORDER BY e.epoch DESC, l.layer DESC, e.id DESC LIMIT ?2");
    statement.bind_blob(1, channel);
    statement.bind_int(2, static_cast<int>(limit));
    std::vector<Event> output;
    while (statement.step() == SQLITE_ROW) {
        output.push_back(Event::deserialize(column_bytes(statement.get(), 0)));
    }
    std::reverse(output.begin(), output.end());
    return output;
}

std::optional<std::uint64_t> EventStore::canonical_layer(const Hash &id) const {
    Statement statement(database_, "SELECT layer FROM event_layers WHERE id = ?1");
    statement.bind_blob(1, id);
    if (statement.step() != SQLITE_ROW) {
        return std::nullopt;
    }
    const sqlite3_int64 layer = sqlite3_column_int64(statement.get(), 0);
    if (layer < 1) {
        throw Error("event store contains an invalid canonical layer");
    }
    return static_cast<std::uint64_t>(layer);
}

std::vector<Bytes> EventStore::load_peer_records(std::uint64_t now_seconds) const {
    Statement statement(database_, "SELECT raw FROM peer_records WHERE expires_at > ?1 "
                                   "ORDER BY identity LIMIT ?2");
    statement.bind_int64(1, now_seconds);
    statement.bind_int(2, static_cast<int>(kMaximumStoredPeerRecords));
    std::vector<Bytes> records;
    while (statement.step() == SQLITE_ROW) {
        records.push_back(column_bytes(statement.get(), 0));
    }
    return records;
}

PeerRecordStoreStatus EventStore::store_peer_record(const PeerRecord &record,
                                                    std::uint64_t observed_at_seconds,
                                                    bool trusted_priority) {
    if (record.network != network_) {
        throw Error("event store refused a peer record from another network");
    }
    const Bytes raw = record.serialize();
    if (raw.size() > kMaximumPeerRecordSize) {
        throw Error("event store refused an oversized peer record");
    }
    const Hash record_id = record.id();
    constexpr std::uint64_t watermark_horizon =
        kPeerRecordMaximumLifetimeSeconds + kPeerRecordFutureSkewSeconds;
    if (observed_at_seconds == 0 ||
        observed_at_seconds > std::numeric_limits<std::uint64_t>::max() - watermark_horizon) {
        throw Error("peer record observation time is invalid");
    }
    std::uint64_t watermark_until =
        std::max(record.expires_at, observed_at_seconds + watermark_horizon);
    {
        Statement existing(
            database_,
            "SELECT sequence, record_id, watermark_until, trusted_priority FROM peer_records "
            "WHERE identity = ?1");
        existing.bind_blob(1, record.identity);
        if (existing.step() == SQLITE_ROW) {
            const sqlite3_int64 stored_sequence = sqlite3_column_int64(existing.get(), 0);
            if (stored_sequence < 1) {
                throw Error("event store contains an invalid peer record sequence");
            }
            const auto sequence = static_cast<std::uint64_t>(stored_sequence);
            const sqlite3_int64 stored_watermark = sqlite3_column_int64(existing.get(), 2);
            if (stored_watermark < 1) {
                throw Error("event store contains an invalid peer record watermark");
            }
            watermark_until =
                std::max(watermark_until, static_cast<std::uint64_t>(stored_watermark));
            const int stored_trusted_priority = sqlite3_column_int(existing.get(), 3);
            if (stored_trusted_priority != 0 && stored_trusted_priority != 1) {
                throw Error("event store contains an invalid peer record trust marker");
            }
            if (trusted_priority && stored_trusted_priority == 0) {
                // Promotion must also happen for duplicate or stale delivery.
                // Once reserved, the row stays reserved until its watermark is
                // pruned; a later open-mode update cannot steal untrusted quota.
                Statement promote(database_, "UPDATE peer_records SET trusted_priority = 1 "
                                             "WHERE identity = ?1");
                promote.bind_blob(1, record.identity);
                promote.step();
            }
            if (record.sequence < sequence) {
                return PeerRecordStoreStatus::stale;
            }
            if (record.sequence == sequence) {
                const Hash stored_id = column_hash(existing.get(), 1);
                return stored_id == record_id ? PeerRecordStoreStatus::duplicate
                                              : PeerRecordStoreStatus::equivocation;
            }
            if (!trusted_priority && stored_trusted_priority == 1) {
                // A key removed from the current allowlist must not keep a
                // protected slot alive indefinitely through open discovery.
                // Preserve its existing rollback watermark, but refuse to
                // extend it as an ordinary record; one full retiring trusted
                // generation has separate bounded headroom until it ages out.
                return PeerRecordStoreStatus::protected_downgrade;
            }
        } else {
            const std::uint64_t count =
                query_uint64(database_, "SELECT COUNT(*) FROM peer_records", "peer record count");
            if (count >= kMaximumStoredPeerRecords) {
                return PeerRecordStoreStatus::quota_exceeded;
            }
            if (!trusted_priority) {
                const std::uint64_t untrusted_count =
                    query_uint64(database_,
                                 "SELECT COUNT(*) FROM peer_records "
                                 "WHERE trusted_priority = 0",
                                 "untrusted peer record count");
                if (untrusted_count >= kMaximumUntrustedStoredPeerRecords) {
                    return PeerRecordStoreStatus::quota_exceeded;
                }
            }
        }
    }

    Statement upsert(database_, "INSERT INTO peer_records(identity, sequence, record_id, "
                                "expires_at, watermark_until, ever_verified, trusted_priority, "
                                "raw) VALUES(?1, ?2, ?3, ?4, ?5, 0, ?6, ?7) "
                                "ON CONFLICT(identity) DO UPDATE SET sequence=excluded.sequence, "
                                "record_id=excluded.record_id, expires_at=excluded.expires_at, "
                                "watermark_until=excluded.watermark_until, "
                                "trusted_priority=excluded.trusted_priority, raw=excluded.raw");
    upsert.bind_blob(1, record.identity);
    upsert.bind_int64(2, record.sequence);
    upsert.bind_blob(3, record_id);
    upsert.bind_int64(4, record.expires_at);
    upsert.bind_int64(5, watermark_until);
    upsert.bind_int(6, trusted_priority ? 1 : 0);
    upsert.bind_blob(7, raw);
    upsert.step();
    return PeerRecordStoreStatus::stored;
}

bool EventStore::peer_record_is_known(const PublicKey &identity) const {
    Statement statement(database_, "SELECT 1 FROM peer_records WHERE identity = ?1");
    statement.bind_blob(1, identity);
    return statement.step() == SQLITE_ROW;
}

bool EventStore::peer_record_has_verified_history(const PublicKey &identity) const {
    Statement statement(database_, "SELECT ever_verified FROM peer_records WHERE identity = ?1");
    statement.bind_blob(1, identity);
    if (statement.step() != SQLITE_ROW) {
        return false;
    }
    const int value = sqlite3_column_int(statement.get(), 0);
    if (value != 0 && value != 1) {
        throw Error("event store contains an invalid peer verification marker");
    }
    return value == 1;
}

bool EventStore::mark_peer_record_verified(const PublicKey &identity, std::uint64_t sequence,
                                           std::uint64_t now_seconds) {
    Statement statement(database_, "UPDATE peer_records SET ever_verified = 1 "
                                   "WHERE identity = ?1 AND sequence = ?2 AND expires_at > ?3");
    statement.bind_blob(1, identity);
    statement.bind_int64(2, sequence);
    statement.bind_int64(3, now_seconds);
    statement.step();
    return sqlite3_changes(database_) == 1;
}

std::uint64_t EventStore::next_peer_record_sequence(const PublicKey &identity,
                                                    std::uint64_t floor) {
    if (floor == 0 || floor == std::numeric_limits<std::uint64_t>::max()) {
        throw Error("peer record sequence floor is invalid");
    }
    std::uint64_t next = floor;
    bool exists = false;
    {
        Statement lookup(database_,
                         "SELECT sequence FROM local_peer_record_sequences WHERE identity = ?1");
        lookup.bind_blob(1, identity);
        if (lookup.step() == SQLITE_ROW) {
            exists = true;
            const sqlite3_int64 stored = sqlite3_column_int64(lookup.get(), 0);
            if (stored < 1 ||
                static_cast<std::uint64_t>(stored) ==
                    static_cast<std::uint64_t>(std::numeric_limits<sqlite3_int64>::max())) {
                throw Error("local peer record sequence is invalid or exhausted");
            }
            next = std::max(next, static_cast<std::uint64_t>(stored) + 1);
        }
    }
    if (!exists) {
        const std::uint64_t count =
            query_uint64(database_, "SELECT COUNT(*) FROM local_peer_record_sequences",
                         "local peer identity count");
        if (count >= kMaximumLocalPeerRecordIdentities) {
            throw Error("local peer record identity history limit reached");
        }
    }
    Statement upsert(database_,
                     "INSERT INTO local_peer_record_sequences(identity, sequence) VALUES(?1, ?2) "
                     "ON CONFLICT(identity) DO UPDATE SET sequence=excluded.sequence");
    upsert.bind_blob(1, identity);
    upsert.bind_int64(2, next);
    upsert.step();
    return next;
}

void EventStore::prune_peer_records(std::uint64_t now_seconds) {
    Statement statement(database_, "DELETE FROM peer_records WHERE watermark_until <= ?1");
    statement.bind_int64(1, now_seconds);
    statement.step();
}

void EventStore::prune_before_epoch(std::uint64_t first_epoch_to_keep) {
    {
        Statement statement(database_, "DELETE FROM events WHERE epoch < ?1");
        statement.bind_int64(1, first_epoch_to_keep);
        statement.step();
    }
    execute(database_, "PRAGMA incremental_vacuum(256)");
    checkpoint(true);
}

std::size_t EventStore::size() const {
    Statement statement(database_, "SELECT COUNT(*) FROM events");
    if (statement.step() != SQLITE_ROW) {
        throw Error("could not count stored events");
    }
    return static_cast<std::size_t>(sqlite3_column_int64(statement.get(), 0));
}

std::uint64_t EventStore::storage_bytes() const {
    if (path_ == ":memory:") {
        return 0;
    }
    const std::uint64_t database_size = existing_file_size(path_);
    const std::uint64_t wal_size = existing_file_size(path_.string() + "-wal");
    const std::uint64_t shm_size = existing_file_size(path_.string() + "-shm");
    if (database_size > std::numeric_limits<std::uint64_t>::max() - wal_size ||
        database_size + wal_size > std::numeric_limits<std::uint64_t>::max() - shm_size) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return database_size + wal_size + shm_size;
}

void EventStore::checkpoint(bool truncate) {
    int log_frames = 0;
    int checkpointed_frames = 0;
    const int mode = truncate ? SQLITE_CHECKPOINT_TRUNCATE : SQLITE_CHECKPOINT_PASSIVE;
    const int result =
        sqlite3_wal_checkpoint_v2(database_, nullptr, mode, &log_frames, &checkpointed_frames);
    if (result != SQLITE_OK && result != SQLITE_BUSY) {
        throw Error(std::string("SQLite checkpoint failed: ") + sqlite3_errmsg(database_));
    }
}

} // namespace kairc
