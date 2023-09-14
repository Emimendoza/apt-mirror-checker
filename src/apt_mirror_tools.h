#pragma once

#include <string>
#include <unordered_map>
#include <chrono>
#include <sstream>
#include <openssl/evp.h>
#include <vector>
#include <atomic>
#include <thread>

constexpr unsigned char SHA256_HASH_SIZE = 32;
constexpr size_t BUFFER_SIZE = 4 * 1024 * 1024; // 4 MB
constexpr unsigned char MAX_ERROR_DEPTH = 5;
template <typename CharT>
std::basic_istream<CharT>& ignore(std::basic_istream<CharT>& in){
    std::string ignoredValue;
    return in >> ignoredValue;
}

class apt_mirror_tools {
public:
    enum class operation{
        mirror,
        verify,
        clean,
        invalid
    };

    struct settings_struct{
        bool safe_mode;
        bool verbose;
        bool bad_lock;
        unsigned char threads;
        operation op;
    };

    explicit apt_mirror_tools(settings_struct set);
    ~apt_mirror_tools();

    void run();
private:
    struct distro_info{
        std::string server;
        std::string distro;
        std::vector<std::string> universes;
        std::string architecture;
    };
    struct package_info {
        unsigned char* hash;
        size_t size;
    };

    std::atomic<bool> interrupted = false;
    std::atomic<bool>* thread_done;

    settings_struct settings;
    std::string repo_path;
    std::string lock_file;
    std::vector<distro_info> distros;
    int good_files;
    int bad_files;
    int ghost_files;
    size_t size_done;
    std::vector<std::string_view> ghost_files_list;
    std::chrono::time_point<std::chrono::system_clock> start_time;
    size_t size_total;
    std::unordered_map<std::string, package_info> packages;
    bool prev_print;
    EVP_MD_CTX *md_ctx;
    char* buffer;
    unsigned char* hash;
    unsigned int hash_len;
    std::stringstream actual_hash_stream;
    int lock_fd;
    std::thread* threads;

    void read_mirror_list();
    void get_lock();
    void get_repo(const std::string& repoPath);
    void read_repo(const std::string& repoPath);
    void get_sha256(const std::string& file_path,unsigned char* sum);
    void sha256_toStr(unsigned char *sum, std::string &sum_str);
    static void str_to_sha256(const std::string& sum_str, unsigned char* sum);
    void add_package(const std::string& package_relative_path, const std::string& package_hash, size_t package_size);

    void stop_threads();
};
