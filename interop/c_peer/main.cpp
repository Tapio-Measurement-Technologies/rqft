// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file
 * @brief Native librqft peer for the interop harness.
 *
 * The peer exposes a deterministic in-memory filesystem and connects a
 * caller-allocated rqft_session_t to stdio or one TCP socket. Controller
 * mode can run a scripted LIST/GET/PUT sequence; responder mode serves
 * requests until the transport closes.
 */
#include "rqft/rqft.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>

namespace {

enum class ActionType {
    List,
    Get,
    Put,
};

struct Action {
    ActionType type;
    std::string path;
};

struct File {
    std::string path;
    std::vector<uint8_t> data;
    uint32_t mtime = 0u;
};

struct MemoryFs {
    std::vector<File> files;
    std::vector<size_t> list_indexes;
    size_t list_pos = 0u;
    int read_index = -1;
    size_t read_pos = 0u;
    std::string write_path;
    std::vector<uint8_t> write_data;
    bool writing = false;
};

struct Options {
    rqft_role_t role = RQFT_ROLE_RESPONDER;
    bool role_set = false;
    bool start = false;
    uint32_t seed = 0xC0FFEEu;
    std::vector<File> files;
    std::vector<Action> actions;
    std::string listen;
    std::string connect;
    uint32_t cancel_after_bytes = 0u;
    bool cancel = false;
};

class Transport {
public:
    Transport() = default;
    Transport(const Transport &) = delete;
    Transport &operator=(const Transport &) = delete;

    ~Transport()
    {
        close_owned();
    }

    void use_stdio()
    {
        in_fd_ = STDIN_FILENO;
        out_fd_ = STDOUT_FILENO;
        owns_io_ = false;
    }

    void listen_tcp(const std::string &spec)
    {
        const auto [host, port] = parse_host_port(spec);
        int server = ::socket(AF_INET, SOCK_STREAM, 0);
        if (server < 0) {
            throw std::runtime_error("socket() failed");
        }
        int yes = 1;
        if (::setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0) {
            ::close(server);
            throw std::runtime_error("setsockopt(SO_REUSEADDR) failed");
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (host.empty()) {
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        } else if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
            ::close(server);
            throw std::runtime_error("listen host must be an IPv4 address");
        }
        if (::bind(server, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
            ::close(server);
            throw std::runtime_error("bind() failed");
        }
        if (::listen(server, 1) != 0) {
            ::close(server);
            throw std::runtime_error("listen() failed");
        }
        int client = ::accept(server, nullptr, nullptr);
        ::close(server);
        if (client < 0) {
            throw std::runtime_error("accept() failed");
        }
        in_fd_ = client;
        out_fd_ = client;
        owns_io_ = true;
    }

    void connect_tcp(const std::string &spec)
    {
        const auto [host, port] = parse_host_port(spec);
        if (host.empty()) {
            throw std::runtime_error("connect host must not be empty");
        }
        int client = ::socket(AF_INET, SOCK_STREAM, 0);
        if (client < 0) {
            throw std::runtime_error("socket() failed");
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
            ::close(client);
            throw std::runtime_error("connect host must be an IPv4 address");
        }
        if (::connect(client, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
            ::close(client);
            throw std::runtime_error("connect() failed");
        }
        in_fd_ = client;
        out_fd_ = client;
        owns_io_ = true;
    }

    bool write_all(const uint8_t *data, size_t len)
    {
        size_t pos = 0u;
        while (pos < len) {
            ssize_t written = ::write(out_fd_, data + pos, len - pos);
            if (written < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return false;
            }
            if (written == 0) {
                return false;
            }
            pos += static_cast<size_t>(written);
        }
        return true;
    }

    int poll_input(int timeout_ms) const
    {
        pollfd pfd{};
        pfd.fd = in_fd_;
        pfd.events = POLLIN;
        for (;;) {
            int rc = ::poll(&pfd, 1u, timeout_ms);
            if (rc < 0 && errno == EINTR) {
                continue;
            }
            if (rc <= 0) {
                return rc;
            }
            if ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
                return 1;
            }
            return 0;
        }
    }

    ssize_t read_some(uint8_t *buf, size_t cap) const
    {
        for (;;) {
            ssize_t got = ::read(in_fd_, buf, cap);
            if (got < 0 && errno == EINTR) {
                continue;
            }
            return got;
        }
    }

private:
    int in_fd_ = STDIN_FILENO;
    int out_fd_ = STDOUT_FILENO;
    bool owns_io_ = false;

    static std::pair<std::string, uint16_t> parse_host_port(const std::string &spec)
    {
        size_t colon = spec.rfind(':');
        if (colon == std::string::npos) {
            throw std::runtime_error("TCP endpoint must be host:port");
        }
        std::string host = spec.substr(0u, colon);
        std::string port_text = spec.substr(colon + 1u);
        char *end = nullptr;
        unsigned long port = std::strtoul(port_text.c_str(), &end, 10);
        if (end == port_text.c_str() || *end != '\0' || port == 0ul ||
            port > std::numeric_limits<uint16_t>::max()) {
            throw std::runtime_error("TCP port must be in [1, 65535]");
        }
        return {host, static_cast<uint16_t>(port)};
    }

    void close_owned()
    {
        if (owns_io_ && in_fd_ >= 0) {
            ::close(in_fd_);
        }
        in_fd_ = -1;
        out_fd_ = -1;
        owns_io_ = false;
    }
};

std::string bytes_to_string(const uint8_t *data, size_t len)
{
    if (len == 0u) {
        return {};
    }
    return std::string(reinterpret_cast<const char *>(data), len);
}

std::string hex_encode(const uint8_t *data, size_t len)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2u);
    for (size_t i = 0u; i < len; i++) {
        uint8_t byte = data[i];
        out.push_back(kHex[byte >> 4u]);
        out.push_back(kHex[byte & 0x0Fu]);
    }
    return out;
}

std::vector<uint8_t> hex_decode(std::string_view text)
{
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return 10 + c - 'a';
        }
        if (c >= 'A' && c <= 'F') {
            return 10 + c - 'A';
        }
        return -1;
    };
    if ((text.size() % 2u) != 0u) {
        throw std::runtime_error("hex file data must have even length");
    }
    std::vector<uint8_t> out;
    out.reserve(text.size() / 2u);
    for (size_t i = 0u; i < text.size(); i += 2u) {
        int hi = nibble(text[i]);
        int lo = nibble(text[i + 1u]);
        if (hi < 0 || lo < 0) {
            throw std::runtime_error("hex file data contains non-hex byte");
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string json_escape(std::string_view text)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(text.size() + 8u);
    for (unsigned char c : text) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 0x20u) {
                out += "\\u00";
                out.push_back(kHex[c >> 4u]);
                out.push_back(kHex[c & 0x0Fu]);
            } else {
                out.push_back(static_cast<char>(c));
            }
            break;
        }
    }
    return out;
}

void log_line(const std::string &line)
{
    std::cerr << line << '\n';
}

void log_event_name(std::string_view event)
{
    std::ostringstream line;
    line << "{\"event\":\"" << event << "\"}";
    log_line(line.str());
}

int find_file(const MemoryFs &fs, const std::string &path)
{
    for (size_t i = 0u; i < fs.files.size(); i++) {
        if (fs.files[i].path == path) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

bool path_under_root(const std::string &path, const std::string &root)
{
    if (root.empty()) {
        return true;
    }
    std::string prefix = root + "/";
    return path.rfind(prefix, 0u) == 0u;
}

bool fs_list_begin(void *user, const uint8_t *root, size_t root_len)
{
    auto *fs = static_cast<MemoryFs *>(user);
    std::string root_path = bytes_to_string(root, root_len);
    fs->list_indexes.clear();
    fs->list_pos = 0u;
    for (size_t i = 0u; i < fs->files.size(); i++) {
        if (path_under_root(fs->files[i].path, root_path)) {
            fs->list_indexes.push_back(i);
        }
    }
    if (!root_path.empty() && fs->list_indexes.empty()) {
        return false;
    }
    std::sort(fs->list_indexes.begin(), fs->list_indexes.end(), [fs](size_t a, size_t b) {
        return fs->files[a].path < fs->files[b].path;
    });
    return true;
}

int fs_list_next(void *user, rqft_fs_entry_t *entry)
{
    auto *fs = static_cast<MemoryFs *>(user);
    if (fs->list_pos >= fs->list_indexes.size()) {
        return 0;
    }
    const File &file = fs->files[fs->list_indexes[fs->list_pos++]];
    if (file.path.size() > RQFT_MAX_PATH ||
        file.data.size() > std::numeric_limits<uint32_t>::max()) {
        return -1;
    }
    std::memset(entry, 0, sizeof(*entry));
    entry->path_len = file.path.size();
    std::memcpy(entry->path, file.path.data(), file.path.size());
    entry->size = static_cast<uint32_t>(file.data.size());
    entry->mtime = file.mtime;
    entry->etype = 0u;
    return 1;
}

void fs_list_close(void *user)
{
    auto *fs = static_cast<MemoryFs *>(user);
    fs->list_indexes.clear();
    fs->list_pos = 0u;
}

bool fs_open_read(void *user, const uint8_t *path, size_t path_len, uint32_t *size)
{
    auto *fs = static_cast<MemoryFs *>(user);
    int index = find_file(*fs, bytes_to_string(path, path_len));
    if (index < 0) {
        return false;
    }
    const File &file = fs->files[static_cast<size_t>(index)];
    if (file.data.size() > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    fs->read_index = index;
    fs->read_pos = 0u;
    *size = static_cast<uint32_t>(file.data.size());
    return true;
}

int fs_read(void *user, uint8_t *buf, size_t cap)
{
    auto *fs = static_cast<MemoryFs *>(user);
    if (fs->read_index < 0) {
        return -1;
    }
    const File &file = fs->files[static_cast<size_t>(fs->read_index)];
    size_t remaining = file.data.size() - fs->read_pos;
    size_t chunk = std::min(remaining, cap);
    if (chunk > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return -1;
    }
    if (chunk > 0u) {
        std::memcpy(buf, file.data.data() + fs->read_pos, chunk);
    }
    fs->read_pos += chunk;
    return static_cast<int>(chunk);
}

void fs_close_read(void *user)
{
    auto *fs = static_cast<MemoryFs *>(user);
    fs->read_index = -1;
    fs->read_pos = 0u;
}

bool fs_open_write(void *user, const uint8_t *path, size_t path_len)
{
    auto *fs = static_cast<MemoryFs *>(user);
    fs->write_path = bytes_to_string(path, path_len);
    fs->write_data.clear();
    fs->writing = true;
    return true;
}

bool fs_write(void *user, const uint8_t *data, size_t len)
{
    auto *fs = static_cast<MemoryFs *>(user);
    if (!fs->writing) {
        return false;
    }
    bool first_write = fs->write_data.empty() && len > 0u;
    fs->write_data.insert(fs->write_data.end(), data, data + len);
    if (first_write) {
        std::ostringstream line;
        line << "{\"event\":\"fs_write_started\",\"path\":\""
             << json_escape(fs->write_path) << "\",\"bytes\":" << len << "}";
        log_line(line.str());
    }
    return true;
}

bool fs_commit(void *user)
{
    auto *fs = static_cast<MemoryFs *>(user);
    if (!fs->writing) {
        return false;
    }
    int index = find_file(*fs, fs->write_path);
    if (index < 0) {
        fs->files.push_back(File{fs->write_path, fs->write_data, 0u});
    } else {
        fs->files[static_cast<size_t>(index)].data = fs->write_data;
    }
    fs->write_path.clear();
    fs->write_data.clear();
    fs->writing = false;
    return true;
}

void fs_discard(void *user)
{
    auto *fs = static_cast<MemoryFs *>(user);
    fs->write_path.clear();
    fs->write_data.clear();
    fs->writing = false;
}

bool fs_remove_file(void *user, const uint8_t *path, size_t path_len)
{
    auto *fs = static_cast<MemoryFs *>(user);
    int index = find_file(*fs, bytes_to_string(path, path_len));
    if (index < 0) {
        return false;
    }
    fs->files.erase(fs->files.begin() + index);
    return true;
}

bool fs_remove_dir(void *user, const uint8_t *path, size_t path_len)
{
    auto *fs = static_cast<MemoryFs *>(user);
    std::string root = bytes_to_string(path, path_len);
    size_t before = fs->files.size();
    fs->files.erase(std::remove_if(fs->files.begin(), fs->files.end(),
                                   [&root](const File &file) {
                                       return path_under_root(file.path, root);
                                   }),
                    fs->files.end());
    return fs->files.size() != before;
}

bool fs_allow_delete(void *user, const uint8_t *path, size_t path_len)
{
    (void)user;
    (void)path;
    (void)path_len;
    return true;
}

const rqft_fs_ops_t kFsOps = {
    fs_list_begin,  fs_list_next,  fs_list_close, fs_open_read, fs_read,
    fs_close_read, fs_open_write, fs_write,      fs_commit,    fs_discard,
    fs_remove_file, fs_remove_dir, fs_allow_delete,
};

class Peer {
public:
    Peer(const Options &options, Transport &transport)
        : options_(options), transport_(transport), fs_{}, sid_state_(options.seed)
    {
        fs_.files = options.files;
        std::memset(&session_, 0, sizeof(session_));
        rqft_session_config_t config{};
        config.role = options.role;
        config.ver_min = RQFT_PROTOCOL_VERSION;
        config.ver_max = RQFT_PROTOCOL_VERSION;
        config.max_payload = RQFT_MAX_PAYLOAD;
        config.window = 4u;
        config.caps = RQFT_CAP_ALLOW_DELETE;
        config.next_sid = &Peer::next_sid;
        config.sid_user = this;
        config.transmit = &Peer::transmit;
        config.transmit_user = this;
        config.on_event = &Peer::on_event;
        config.event_user = this;
        config.fs = &kFsOps;
        config.fs_user = &fs_;
        rqft_result_t result = rqft_session_init(&session_, &config);
        if (result != RQFT_OK) {
            throw std::runtime_error("rqft_session_init failed");
        }
    }

    void maybe_start(uint32_t now_ms)
    {
        if (options_.start && !started_) {
            started_ = true;
            rqft_result_t result = rqft_session_start(&session_, now_ms);
            if (result != RQFT_OK) {
                fail("start", result);
            }
        }
    }

    void receive(const uint8_t *data, size_t len, uint32_t now_ms)
    {
        rqft_session_receive(&session_, data, len, now_ms);
    }

    void poll(uint32_t now_ms)
    {
        rqft_session_poll(&session_, now_ms);
    }

    bool work_pending() const
    {
        return rqft_session_work_pending(&session_);
    }

    bool next_timeout(uint32_t *deadline_ms) const
    {
        return rqft_session_next_timeout(&session_, deadline_ms);
    }

    bool failed() const
    {
        return failed_;
    }

    /** Cancel the active session with ABORT(E_USER) once the configured
     * transmit-byte threshold is crossed. */
    void maybe_cancel(uint32_t now_ms)
    {
        if (!options_.cancel || cancelled_ || !active_ ||
            tx_bytes_ < options_.cancel_after_bytes) {
            return;
        }
        cancelled_ = true;
        log_event_name("cancelled");
        rqft_session_abort(&session_, RQFT_ABORT_E_USER, now_ms);
    }

    bool cancel_complete() const
    {
        return cancelled_ && !active_;
    }

    bool controller_complete() const
    {
        return options_.role == RQFT_ROLE_CONTROLLER &&
               action_index_ >= options_.actions.size() && !action_pending_ && active_ &&
               !failed_;
    }

    void dump_files() const
    {
        std::vector<const File *> files;
        files.reserve(fs_.files.size());
        for (const File &file : fs_.files) {
            files.push_back(&file);
        }
        std::sort(files.begin(), files.end(), [](const File *a, const File *b) {
            return a->path < b->path;
        });
        for (const File *file : files) {
            std::ostringstream line;
            line << "{\"event\":\"fs_file\",\"path\":\"" << json_escape(file->path)
                 << "\",\"hex\":\"" << hex_encode(file->data.data(), file->data.size())
                 << "\"}";
            log_line(line.str());
        }
    }

    void maybe_start_action(uint32_t now_ms)
    {
        if (!active_ || failed_ || action_pending_ ||
            action_index_ >= options_.actions.size()) {
            return;
        }
        const Action &action = options_.actions[action_index_];
        rqft_result_t result = RQFT_ERR_MALFORMED;
        if (action.type == ActionType::List) {
            result = rqft_session_request_list(
                &session_, reinterpret_cast<const uint8_t *>(action.path.data()),
                action.path.size(), true, now_ms);
        } else if (action.type == ActionType::Get) {
            result = rqft_session_request_get(
                &session_, reinterpret_cast<const uint8_t *>(action.path.data()),
                action.path.size(), now_ms);
        } else {
            result = rqft_session_request_put(
                &session_, reinterpret_cast<const uint8_t *>(action.path.data()),
                action.path.size(), now_ms);
        }
        if (result != RQFT_OK) {
            fail("request", result);
            return;
        }
        action_pending_ = true;
        std::ostringstream line;
        line << "{\"event\":\"action_started\",\"kind\":\"" << action_name(action.type)
             << "\",\"path\":\"" << json_escape(action.path) << "\"}";
        log_line(line.str());
    }

private:
    const Options &options_;
    Transport &transport_;
    MemoryFs fs_;
    rqft_session_t session_{};
    uint32_t sid_state_ = 0u;
    bool started_ = false;
    bool active_ = false;
    bool failed_ = false;
    bool cancelled_ = false;
    size_t tx_bytes_ = 0u;
    bool action_pending_ = false;
    size_t action_index_ = 0u;

    static const char *action_name(ActionType type)
    {
        switch (type) {
        case ActionType::List:
            return "list";
        case ActionType::Get:
            return "get";
        case ActionType::Put:
            return "put";
        }
        return "unknown";
    }

    static uint8_t next_sid(void *user)
    {
        auto *peer = static_cast<Peer *>(user);
        peer->sid_state_ = peer->sid_state_ * 1103515245u + 12345u;
        uint8_t sid = static_cast<uint8_t>((peer->sid_state_ >> 16u) & 0xFFu);
        return sid == 0u ? 1u : sid;
    }

    static void transmit(void *user, const uint8_t *wire, size_t wire_len)
    {
        auto *peer = static_cast<Peer *>(user);
        peer->tx_bytes_ += wire_len;
        if (!peer->transport_.write_all(wire, wire_len)) {
            peer->failed_ = true;
            log_event_name("transport_write_failed");
        }
    }

    static void on_event(void *user, const rqft_session_event_t *event)
    {
        static_cast<Peer *>(user)->handle_event(*event);
    }

    void handle_event(const rqft_session_event_t &event)
    {
        switch (event.type) {
        case RQFT_SESSION_EVENT_ESTABLISHED:
            active_ = true;
            log_established(event.u.established);
            break;
        case RQFT_SESSION_EVENT_ENDED:
            active_ = false;
            log_ended(event.u.ended);
            break;
        case RQFT_SESSION_EVENT_PASSTHROUGH:
            log_passthrough(event.u.passthrough);
            break;
        case RQFT_SESSION_EVENT_LIST_ENTRY:
            log_list_entry(event.u.list_entry);
            break;
        case RQFT_SESSION_EVENT_LIST_DONE:
            log_list_done(event.u.list_done);
            complete_action(ActionType::List);
            break;
        case RQFT_SESSION_EVENT_LIST_SKIP:
            log_list_skip(event.u.list_skip);
            break;
        case RQFT_SESSION_EVENT_GET_DONE:
            log_get_done(event.u.get_done);
            complete_action(ActionType::Get);
            break;
        case RQFT_SESSION_EVENT_GET_SERVED:
            log_get_served(event.u.get_served);
            break;
        case RQFT_SESSION_EVENT_PUT_DONE:
            log_put_done(event.u.put_done);
            complete_action(ActionType::Put);
            break;
        case RQFT_SESSION_EVENT_DEL_DONE:
            log_event_name("del_done");
            break;
        case RQFT_SESSION_EVENT_PLAN:
            log_plan(event.u.plan);
            break;
        case RQFT_SESSION_EVENT_NOTIFY:
            log_notify(event.u.notify);
            break;
        case RQFT_SESSION_EVENT_OP_FAILED:
            log_op_failed(event.u.op_failed);
            failed_ = true;
            action_pending_ = false;
            break;
        }
    }

    void complete_action(ActionType type)
    {
        if (action_pending_ && action_index_ < options_.actions.size() &&
            options_.actions[action_index_].type == type) {
            action_pending_ = false;
            action_index_++;
        }
    }

    void fail(std::string_view where, rqft_result_t result)
    {
        failed_ = true;
        std::ostringstream line;
        line << "{\"event\":\"error\",\"where\":\"" << where << "\",\"code\":"
             << static_cast<int>(result) << "}";
        log_line(line.str());
    }

    static void log_established(const rqft_session_established_t &event)
    {
        std::ostringstream line;
        line << "{\"event\":\"established\",\"sid\":" << static_cast<int>(event.sid)
             << ",\"version\":" << static_cast<int>(event.version) << ",\"role\":"
             << static_cast<int>(event.role) << ",\"max_payload\":" << event.max_payload
             << ",\"window\":" << static_cast<int>(event.window)
             << ",\"peer_caps\":" << static_cast<int>(event.peer_caps) << "}";
        log_line(line.str());
    }

    static void log_ended(const rqft_session_ended_t &event)
    {
        std::ostringstream line;
        line << "{\"event\":\"ended\",\"reason\":" << static_cast<int>(event.reason)
             << ",\"from_peer\":" << (event.from_peer ? "true" : "false") << "}";
        log_line(line.str());
    }

    static void log_passthrough(const rqft_session_passthrough_t &event)
    {
        std::ostringstream line;
        line << "{\"event\":\"passthrough\",\"hex\":\""
             << hex_encode(event.data, event.len) << "\"}";
        log_line(line.str());
    }

    static void log_list_entry(const rqft_session_list_entry_t &event)
    {
        std::string path = bytes_to_string(event.path, event.path_len);
        std::ostringstream line;
        line << "{\"event\":\"list_entry\",\"path\":\"" << json_escape(path)
             << "\",\"size\":" << event.size << ",\"mtime\":" << event.mtime
             << ",\"crc32\":";
        if (event.has_crc) {
            line << event.crc32;
        } else {
            line << "null";
        }
        line << "}";
        log_line(line.str());
    }

    static void log_list_done(const rqft_session_list_done_t &event)
    {
        std::ostringstream line;
        line << "{\"event\":\"list_done\",\"count\":" << event.count << "}";
        log_line(line.str());
    }

    static void log_list_skip(const rqft_session_list_skip_t &event)
    {
        std::ostringstream line;
        line << "{\"event\":\"list_skip\",\"code\":" << static_cast<int>(event.code)
             << ",\"detail\":" << event.detail << "}";
        log_line(line.str());
    }

    static void log_get_done(const rqft_session_get_done_t &event)
    {
        std::string path = bytes_to_string(event.path, event.path_len);
        std::ostringstream line;
        line << "{\"event\":\"get_done\",\"path\":\"" << json_escape(path)
             << "\",\"size\":" << event.size << ",\"crc32\":" << event.crc32
             << "}";
        log_line(line.str());
    }

    static void log_get_served(const rqft_session_get_served_t &event)
    {
        std::string path = bytes_to_string(event.path, event.path_len);
        std::ostringstream line;
        line << "{\"event\":\"get_served\",\"path\":\"" << json_escape(path)
             << "\",\"size\":" << event.size << ",\"crc32\":" << event.crc32
             << "}";
        log_line(line.str());
    }

    static void log_put_done(const rqft_session_put_done_t &event)
    {
        std::string path = bytes_to_string(event.path, event.path_len);
        std::ostringstream line;
        line << "{\"event\":\"put_done\",\"path\":\"" << json_escape(path)
             << "\",\"size\":" << event.size << ",\"crc32\":" << event.crc32
             << "}";
        log_line(line.str());
    }

    static void log_plan(const rqft_session_plan_t &event)
    {
        std::ostringstream line;
        line << "{\"event\":\"plan\",\"nfiles\":" << event.nfiles
             << ",\"nbytes\":" << event.nbytes << "}";
        log_line(line.str());
    }

    static void log_notify(const rqft_session_notify_t &event)
    {
        std::ostringstream line;
        line << "{\"event\":\"notify\",\"flags\":" << event.flags << "}";
        log_line(line.str());
    }

    static void log_op_failed(const rqft_session_op_failed_t &event)
    {
        std::string path = bytes_to_string(event.path, event.path_len);
        std::ostringstream line;
        line << "{\"event\":\"op_failed\",\"request\":" << static_cast<int>(event.request)
             << ",\"code\":" << static_cast<int>(event.code)
             << ",\"detail\":" << event.detail << ",\"path\":\"" << json_escape(path)
             << "\"}";
        log_line(line.str());
    }
};

void usage()
{
    std::cerr
        << "usage: c_peer --role controller|responder [--seed N]\n"
        << "              [--file PATH=text:DATA|hex:HEX] [--list ROOT]\n"
        << "              [--get PATH] [--put PATH] [--listen HOST:PORT]\n"
        << "              [--connect HOST:PORT] [--start]\n"
        << "              [--cancel-after-bytes N]\n";
}

File parse_file_arg(const std::string &spec)
{
    size_t eq = spec.find('=');
    if (eq == std::string::npos || eq == 0u) {
        throw std::runtime_error("--file expects PATH=DATA");
    }
    File file;
    file.path = spec.substr(0u, eq);
    std::string data = spec.substr(eq + 1u);
    if (data.rfind("hex:", 0u) == 0u) {
        file.data = hex_decode(std::string_view(data).substr(4u));
    } else {
        if (data.rfind("text:", 0u) == 0u) {
            data = data.substr(5u);
        }
        file.data.assign(data.begin(), data.end());
    }
    return file;
}

uint32_t parse_u32(const std::string &text)
{
    char *end = nullptr;
    unsigned long value = std::strtoul(text.c_str(), &end, 0);
    if (end == text.c_str() || *end != '\0' ||
        value > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("integer argument out of range");
    }
    return static_cast<uint32_t>(value);
}

Options parse_args(int argc, char **argv)
{
    Options options;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        auto need_value = [&](std::string_view name) -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error(std::string(name) + " needs a value");
            }
            i++;
            return argv[i];
        };
        if (arg == "--role") {
            std::string value = need_value("--role");
            if (value == "controller") {
                options.role = RQFT_ROLE_CONTROLLER;
            } else if (value == "responder") {
                options.role = RQFT_ROLE_RESPONDER;
            } else {
                throw std::runtime_error("--role must be controller or responder");
            }
            options.role_set = true;
        } else if (arg == "--seed") {
            options.seed = parse_u32(need_value("--seed"));
        } else if (arg == "--file") {
            options.files.push_back(parse_file_arg(need_value("--file")));
        } else if (arg == "--list") {
            options.actions.push_back(Action{ActionType::List, need_value("--list")});
        } else if (arg == "--get") {
            options.actions.push_back(Action{ActionType::Get, need_value("--get")});
        } else if (arg == "--put") {
            options.actions.push_back(Action{ActionType::Put, need_value("--put")});
        } else if (arg == "--listen") {
            options.listen = need_value("--listen");
        } else if (arg == "--connect") {
            options.connect = need_value("--connect");
        } else if (arg == "--cancel-after-bytes") {
            options.cancel_after_bytes = parse_u32(need_value("--cancel-after-bytes"));
            options.cancel = true;
        } else if (arg == "--start") {
            options.start = true;
        } else if (arg == "--help") {
            usage();
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + arg);
        }
    }
    if (!options.role_set) {
        throw std::runtime_error("--role is required");
    }
    if (!options.listen.empty() && !options.connect.empty()) {
        throw std::runtime_error("--listen and --connect are mutually exclusive");
    }
    if (options.role == RQFT_ROLE_CONTROLLER) {
        options.start = true;
    }
    return options;
}

uint32_t now_ms(const std::chrono::steady_clock::time_point &start)
{
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    if (elapsed.count() < 0) {
        return 0u;
    }
    auto max_ms = static_cast<decltype(elapsed.count())>(
        std::numeric_limits<uint32_t>::max());
    if (elapsed.count() > max_ms) {
        return std::numeric_limits<uint32_t>::max();
    }
    return static_cast<uint32_t>(elapsed.count());
}

int poll_timeout_ms(const Peer &peer, uint32_t now)
{
    uint32_t deadline = 0u;
    if (!peer.next_timeout(&deadline)) {
        return 5;
    }
    if (deadline <= now) {
        return 0;
    }
    uint32_t delta = deadline - now;
    return static_cast<int>(std::min<uint32_t>(delta, 5u));
}

int run_peer(const Options &options, Transport &transport)
{
    Peer peer(options, transport);
    const auto start = std::chrono::steady_clock::now();
    uint8_t buf[4096];

    log_event_name("ready");
    peer.maybe_start(now_ms(start));
    for (;;) {
        uint32_t now = now_ms(start);
        peer.maybe_start_action(now);
        peer.maybe_cancel(now);
        now = now_ms(start);
        if (peer.cancel_complete()) {
            peer.dump_files();
            log_event_name("complete");
            return peer.failed() ? 1 : 0;
        }
        if (peer.controller_complete()) {
            peer.dump_files();
            log_event_name("complete");
            return peer.failed() ? 1 : 0;
        }
        if (peer.failed()) {
            peer.dump_files();
            log_event_name("complete");
            return 1;
        }

        int ready = transport.poll_input(peer.work_pending() ? 0 : poll_timeout_ms(peer, now));
        now = now_ms(start);
        while (ready > 0) {
            ssize_t got = transport.read_some(buf, sizeof(buf));
            if (got < 0) {
                log_event_name("transport_read_failed");
                return 1;
            }
            if (got == 0) {
                peer.dump_files();
                log_event_name("complete");
                return peer.failed() ? 1 : 0;
            }
            peer.receive(buf, static_cast<size_t>(got), now);
            ready = transport.poll_input(0);
            now = now_ms(start);
        }
        peer.poll(now);
    }
}

} // namespace

int main(int argc, char **argv)
{
    std::ios::sync_with_stdio(false);
    std::cerr.setf(std::ios::unitbuf);
    try {
        Options options = parse_args(argc, argv);
        Transport transport;
        if (!options.listen.empty()) {
            transport.listen_tcp(options.listen);
        } else if (!options.connect.empty()) {
            transport.connect_tcp(options.connect);
        } else {
            transport.use_stdio();
        }
        return run_peer(options, transport);
    } catch (const std::exception &exc) {
        std::cerr << "{\"event\":\"fatal\",\"message\":\"" << json_escape(exc.what())
                  << "\"}\n";
        return 2;
    }
}
