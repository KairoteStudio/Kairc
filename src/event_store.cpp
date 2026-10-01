#include "kairc/event_store.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <limits>
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

EventStore::EventStore(const std::filesystem::path &path, Hash network) : network_(network) {
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
        execute(database_, "PRAGMA journal_mode = WAL");
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

    const Bytes raw = event.serialize();
    execute(database_, "BEGIN IMMEDIATE");
    try {
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

        const Hash root = epoch_root(network_, event.epoch());
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
    Statement statement(
        database_, "SELECT raw FROM events WHERE channel = ?1 ORDER BY timestamp_ms DESC LIMIT ?2");
    statement.bind_blob(1, channel);
    statement.bind_int(2, static_cast<int>(limit));
    std::vector<Event> output;
    while (statement.step() == SQLITE_ROW) {
        output.push_back(Event::deserialize(column_bytes(statement.get(), 0)));
    }
    std::reverse(output.begin(), output.end());
    return output;
}

void EventStore::prune_before_epoch(std::uint64_t first_epoch_to_keep) {
    Statement statement(database_, "DELETE FROM events WHERE epoch < ?1");
    statement.bind_int64(1, first_epoch_to_keep);
    statement.step();
}

std::size_t EventStore::size() const {
    Statement statement(database_, "SELECT COUNT(*) FROM events");
    if (statement.step() != SQLITE_ROW) {
        throw Error("could not count stored events");
    }
    return static_cast<std::size_t>(sqlite3_column_int64(statement.get(), 0));
}

} // namespace kairc
