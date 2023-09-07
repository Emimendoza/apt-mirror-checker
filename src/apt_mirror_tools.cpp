#include <fstream>
#include <cstring>
#include <iomanip>
#include "apt_mirror_tools.h"
#include "print.h"

apt_mirror_tools::apt_mirror_tools(apt_mirror_tools::settings_struct set) {
    settings = set;
    good_files = 0;
    bad_files = 0;
    zombie_files = 0;
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

}

apt_mirror_tools::~apt_mirror_tools() {
    for(const auto& package: packages){
        delete[] package.second.hash;
    }
    delete[] buffer;
    delete[] hash;
    EVP_MD_CTX_free(md_ctx);
}

void apt_mirror_tools::read_repo() {

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
inline void apt_mirror_tools::sha256_toStr(unsigned char* sum, std::string& sum_str){
    for (unsigned int i = 0; i < SHA256_HASH_SIZE; i++) {
        actual_hash_stream << std::setw(2) << static_cast<unsigned>(sum[i]);
    }
    sum_str = actual_hash_stream.str();
    actual_hash_stream.str("");
}

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

}
