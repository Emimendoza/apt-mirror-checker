#include <sys/file.h>
#include <thread>
#include <fstream>
#include <cstring>
#include <iomanip>
#include "apt_mirror_tools.h"
#include "print.h"

// Convert a hex character to an integer
// Is this really the fastest way?
// TODO: Benchmark this
inline constexpr char hex_char_to_int(const char& c) {
    switch (c) {
        case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			return c - '0';
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
			return c - 'a' + 10;
        default:
            throw std::runtime_error("Invalid hex character");
    }
}

apt_mirror_tools::apt_mirror_tools(apt_mirror_tools::settings_struct set) {
    settings = set;
    lock_fd = -1;
    good_files = 0;
    bad_files = 0;
    ghost_files = 0;
    size_done = 0;
    start_time = std::chrono::system_clock::now();
    size_total = 0;
    packages = std::unordered_map<std::string, package_info>();
    prev_print = false;
    md_ctx = EVP_MD_CTX_new();
    buffer = new char[BUFFER_SIZE];
    hash = new unsigned char[SHA256_HASH_SIZE];
    hash_len = 0;
    actual_hash_stream = std::stringstream();
    threads = new std::thread[settings.threads];
    thread_done = new std::atomic<bool>[settings.threads];
    read_mirror_list();
    get_lock();
}

apt_mirror_tools::~apt_mirror_tools() {
    for(const auto& package: packages){
        delete[] package.second.hash;
    }
    delete[] buffer;
    delete[] hash;
    delete[] threads;
    delete[] thread_done;
    EVP_MD_CTX_free(md_ctx);
}


void apt_mirror_tools::get_repo(const std::string &repoPath) {

}

void apt_mirror_tools::read_repo(const std::string& repoPath) {

}

void apt_mirror_tools::read_mirror_list() {
    std::ifstream file("/etc/apt/mirror.list");
    if (!file) {
        throw std::runtime_error("Failed to open file: /etc/apt/mirror.list");
    }
    std::string default_arch = "amd64";
    std::string line;
    std::stringstream ss;
    std::string token;
    while (file){
        std::getline(file, line);
        ss = std::stringstream(line);
        ss >> token;
        if (token == "set"){
            std::string param;
            ss >> param;
            if (param == "base_path") {
                std::string base_path;
                ss >> base_path;
                repo_path = base_path + "/mirror/";
                if (settings.bad_lock)
                    lock_file = "./apt-mirror.lock";
                else
                    lock_file = base_path + "/var/apt-mirror.lock";
            } else if (param == "defaultarch") {
                ss >> default_arch;
            }
        }
        else if (token.starts_with("deb")){
            distro_info distro;
            ss >> distro.server;
            ss >> distro.distro;
            if (token.length() == 3){
                distro.architecture = default_arch;
            } else{
                distro.architecture = token.substr(4);
            }
            while(ss){
                std::string universe;
                ss >> universe;
                distro.universes.push_back(universe);
            }
            distros.push_back(distro);
        }
    }
}



// Convert a string of hex characters to a SHA256 hash
// The string will be in the format of: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
// Note how there is no Ox at the beginning
inline void apt_mirror_tools::str_to_sha256(const std::string &sum_str, unsigned char *sum) {
    for (unsigned int i = 0; i < SHA256_HASH_SIZE; i++) {
        sum[i] = (hex_char_to_int(sum_str[i * 2]) << 4) | hex_char_to_int(sum_str[i * 2 + 1]);
    }
}
// Convert a SHA256 hash to a string of hex characters
inline void apt_mirror_tools::sha256_toStr(unsigned char* sum, std::string& sum_str){
    for (unsigned int i = 0; i < SHA256_HASH_SIZE; i++) {
        actual_hash_stream << std::setw(2) << static_cast<unsigned>(sum[i]);
    }
    sum_str = actual_hash_stream.str();
    actual_hash_stream.str("");
}
// Calculate the SHA256 hash of a file
inline void apt_mirror_tools::get_sha256(const std::string &file_path, unsigned char *sum) {
    EVP_MD_CTX_reset(md_ctx);

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("Failed to initialize OpenSSL digest");
    }

    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + file_path);
    }

    size_t total_bytes_read = 0;

    while (file) {
        file.read(buffer, BUFFER_SIZE);
        size_t bytes_read = file.gcount();
        total_bytes_read += bytes_read;
        EVP_DigestUpdate(md_ctx, buffer, bytes_read);
    }

    file.close();

    if (total_bytes_read % BUFFER_SIZE == 0) {
        // Handle the case when the file size is exactly a multiple of the buffer size
        EVP_DigestUpdate(md_ctx, buffer, 0);
    }

    if (EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to finalize OpenSSL digest");
    }
    memcpy(sum, hash, SHA256_HASH_SIZE);
}

void apt_mirror_tools::get_lock() {
    if (settings.bad_lock)
        return;
    do{
        lock_fd = open(lock_file.c_str(), O_RDONLY | O_CREAT| O_NONBLOCK, 0666);
        // Wait a bit if the file is locked
        if (lock_fd == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)){
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    } while (lock_fd == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
    if (lock_fd == -1){
        throw std::runtime_error("Failed to open file: " + lock_file);
    }
    // The same but now to acquire the lock
    int lock_status = -1;
    do {
        lock_status = flock(lock_fd, LOCK_EX | LOCK_NB);
        if (lock_status == -1 && (errno == EWOULDBLOCK)){
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    } while (lock_status == -1 && (errno == EWOULDBLOCK));

    if (flock(lock_fd, LOCK_EX | LOCK_NB) == -1){
        throw std::runtime_error("Failed to lock file: " + lock_file);
    }
}

void apt_mirror_tools::run() {
    switch (settings.op) {
        case operation::mirror:
            // Mirror case
            break;
        case operation::verify:
            // Verify case
            break;
        case operation::clean:
            // Clean case
            break;
        default:
            throw std::runtime_error("Invalid operation");
    }
}

void apt_mirror_tools::stop_threads() {
    // This is for when a signal is caught, we want to gracefully stop the threads
    interrupted = true;
    std::this_thread::sleep_for(std::chrono::seconds(5));
    // If the threads are still running, we detach them
    for (int i = 0; i < settings.threads; i++){
        if (!thread_done[i]){
            threads[i].detach();
        }
    }
    // Join finished threads
    for (int i = 0; i < settings.threads; i++){
        if (threads[i].joinable() && thread_done[i]){
            threads[i].join();
        }
    }
}

void apt_mirror_tools::add_package(const std::string &package_relative_path, const std::string &package_hash,
                                   size_t package_size) {
    package_info package{};
    package.hash = new unsigned char[SHA256_HASH_SIZE];
    str_to_sha256(package_hash, package.hash);
    package.size = package_size;
    packages[package_relative_path] = package;
}
