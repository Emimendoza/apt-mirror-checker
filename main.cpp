#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <iterator>
#include <cstring>
#include <openssl/evp.h>
#include <curl/curl.h>
#include <unistd.h>
#include <sys/file.h>
#include <unordered_map>
#include <iomanip>
#include <fcntl.h>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <array>
#include <fmt/core.h>

constexpr size_t BUFFER_SIZE = 65536;
constexpr unsigned char MAX_ERROR_DEPTH = 5;
template <typename CharT>
std::basic_istream<CharT>& ignore(std::basic_istream<CharT>& in){
    std::string ignoredValue;
    return in >> ignoredValue;
}

std::string format_file_size(double file_size_bytes) {
    const std::vector<std::string> units{"B", "KB", "MB", "GB", "TB"};
    size_t unit_index = 0;
    while (file_size_bytes > 1024 && unit_index < units.size() - 1) {
        file_size_bytes /= 1024.0;
        unit_index++;
    }
    std::stringstream formatted;
    formatted << std::fixed << std::setprecision(2) << file_size_bytes << " " << units[unit_index];
    return formatted.str();
}

std::string get_file_contents(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file) {
        throw std::runtime_error("Failed to read file: " + file_path);
    }
    std::ostringstream content_stream;
    content_stream << file.rdbuf();
    return content_stream.str();
}

bool get_next(const std::string& string, size_t& start, std::string& store, const std::string& delim) {
    size_t next = string.find(delim, start);
    if (next != std::string::npos) {
        store.assign(string, start, next - start);
        start = next + delim.length();
    } else {
        store.assign(string, start, std::string::npos);
        start = next;
    }
    return (start != std::string::npos);
}


size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::ostream& stream = *static_cast<std::ostream*>(userdata);
    stream.write(ptr, size * nmemb);
    return size * nmemb;
}

void check_file(const std::string &file_path, const size_t &size_total, const bool &safe_mode, const bool &verbose,
                const std::string &repo_path,
                const std::unordered_map<std::string, std::pair<std::string, size_t>> &packages, int &good_files,
                int &bad_files, size_t &size_done, bool& prev_print, const std::string &server, const auto& start_time,
                const unsigned char& depth) {
    if (depth > MAX_ERROR_DEPTH)
    {
        throw std::runtime_error("Max error depth exceeded: This could be caused by the downloaded file hash not "
                                 "matching the expected hash too many times or by too many errors while downloading a file.\n");
    }
    size_t file_size = 0;
    try {
        std::string_view relative_file(file_path);
        relative_file.remove_prefix(repo_path.length() + 1);

        // Calculate the hash of the file
        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file: " + file_path);
        }

        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            file.close();
            throw std::runtime_error("Failed to create OpenSSL context");
        }

        if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr) != 1) {
            EVP_MD_CTX_free(md_ctx);
            file.close();
            throw std::runtime_error("Failed to initialize OpenSSL digest");
        }

        std::array<char, BUFFER_SIZE> buffer{};
        size_t total_bytes_read = 0;

        while (file) {
            file.read(buffer.data(), BUFFER_SIZE);
            size_t bytes_read = file.gcount();
            total_bytes_read += bytes_read;
            EVP_DigestUpdate(md_ctx, buffer.data(), bytes_read);
        }

        file.close();

        if (total_bytes_read % BUFFER_SIZE == 0) {
            // Handle the case when the file size is exactly a multiple of the buffer size
            EVP_DigestUpdate(md_ctx, buffer.data(), 0);
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;

        if (EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1) {
            EVP_MD_CTX_free(md_ctx);
            throw std::runtime_error("Failed to finalize OpenSSL digest");
        }

        EVP_MD_CTX_free(md_ctx);

        std::stringstream actual_hash_stream;
        actual_hash_stream << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < hash_len; i++) {
            actual_hash_stream << std::setw(2) << static_cast<unsigned>(hash[i]);
        }

        std::string actual_hash = actual_hash_stream.str();

        auto file_info_iter = packages.find(std::string(relative_file));
        if (file_info_iter != packages.end()) {
            const auto &file_info = file_info_iter->second;
            const std::string &expected_hash = file_info.first;
            file_size = file_info.second;
            if (actual_hash != expected_hash) {
                if (depth==0){
                    bad_files++;
                }
                prev_print = false;
                std::cout << "\x1b[A[BAD FILE] " << relative_file << " - actual hash: " << actual_hash
                          << ", expected hash: "
                          << expected_hash << '\n';
                if (!safe_mode) {
                    std::cout << "Downloading good version of " << file_path << "..." << '\n';

                    // Remove the existing file
                    if (std::remove(file_path.c_str()) != 0) {
                        throw std::runtime_error("Error deleting file: " + file_path);
                    }

                    // Download the good version of the file
                    std::string download_url = server + "/ubuntu/" + std::string(relative_file);
                    CURL *curl = curl_easy_init();
                    if (curl) {
                        std::ofstream output_file(file_path, std::ios::binary);
                        if (!output_file) {
                            curl_easy_cleanup(curl);
                            throw std::runtime_error("Failed to open output file: " + file_path);
                        }

                        output_file.rdbuf()->pubsetbuf(nullptr, 0);  // Disable output buffering

                        curl_easy_setopt(curl, CURLOPT_URL, download_url.c_str());
                        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
                        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output_file);

                        CURLcode res = curl_easy_perform(curl);
                        if (res != CURLE_OK) {
                            output_file.close();
                            std::remove(file_path.c_str());
                            curl_easy_cleanup(curl);
                            throw std::runtime_error("Error downloading file: " + download_url);
                        }

                        output_file.close();
                        curl_easy_cleanup(curl);
                    } else {
                        throw std::runtime_error("Failed to initialize cURL");
                    }
                    // Verify that the downloaded file is correct
                    check_file(file_path, size_total,safe_mode,verbose,repo_path,packages,good_files,bad_files,
                               size_done,prev_print,server,start_time,depth+1);
                }
            } else if (verbose) {
                std::cout << "\x1b[A[GOOD FILE] " << relative_file << " - hash: " << actual_hash << '\n';
                prev_print = false;
                if (depth == 0){
                    good_files++;
                }
            } else if (depth == 0) {
                good_files++;
            }
        } else {
            if (verbose) {
                std::cout << "\x1b[A[GHOST FILE] " << relative_file << " - hash: " << actual_hash << '\n';
                prev_print = false;
            }
            good_files++;
        }
        if (prev_print) {
            std::cout << "\x1b[A\x1b[K";
        }
        // Rewrite to make more legible
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time);
        double rate = (size_done*1000.0)/duration.count();
        unsigned int seconds_total = (size_total)/rate;
        unsigned int seconds = duration.count()/1000;
        std::cout << fmt::format("{} | % Done: {:.2f}% | Good: {} | Bad: {} | % Good: {:.2f}% | {}/s | {:02}:{:02}:{:02}/{:02}:{:02}:{:02}\n",
                                 format_file_size(size_done),
                                 (double)(size_done * 100) / size_total,
                                 good_files,
                                 bad_files,
                                 (double)(good_files * 100) / (good_files + bad_files),
                                 format_file_size(rate),
                                 seconds / 3600,
                                 (seconds % 3600) / 60,
                                 seconds % 60,
                                 seconds_total / 3600,
                                 (seconds_total % 3600) / 60,
                                 seconds_total % 60);
        prev_print = true;

    }
    catch (std::runtime_error& error)
    {
        std::cerr << "\n" << error.what() << "\n";
        if (depth == MAX_ERROR_DEPTH)
        {
            std::cerr << "\nMax Error Handling Depth Exceeded\n";
            throw;
        }
        sleep( 10);
        check_file(file_path, size_total,safe_mode,verbose,repo_path,packages,good_files,bad_files,size_done,prev_print,
                   server,start_time,depth+1);
    }
    if (depth == 0){
        size_done += file_size;
    }
}

void walk_directory(const std::string& directoryPath, const size_t& size_total, const bool& safe_mode, const bool& verbose, const std::string& repo_path,
                    const std::unordered_map<std::string, std::pair<std::string, size_t>>& packages,
                    int& good_files, int& bad_files, size_t& size_done, bool& prev_print, const std::string& server,
                    const auto& start_time)
{
    // Process the directory
    for (const auto& entry : std::filesystem::directory_iterator(directoryPath))
    {
        const auto& path = entry.path();
        if (std::filesystem::is_directory(path))
        {
            // Recursive call for subdirectories
            walk_directory(path.string(),size_total, safe_mode, verbose, repo_path, packages, good_files, bad_files,
                           size_done, prev_print, server, start_time);
        }
        else if (std::filesystem::is_regular_file(path))
        {
            // Process regular files
            check_file(path.string(), size_total, safe_mode, verbose, repo_path, packages, good_files, bad_files,
                       size_done, prev_print, server, start_time, 0);
        }
    }
}

int main(int argc, char* argv[]) {
    std::string mirror_file = "/etc/apt/mirror.list";
    std::string repo_path;
    std::vector<std::string> distros;
    std::vector<std::string> distros2 = {"main", "multiverse", "restricted", "universe"};
    std::vector<std::string> archs = {"amd64", "i386"};
    std::string server;
    bool repo_updated = false;
    std::string lock_file;
    std::unordered_map<std::string, std::pair<std::string, size_t>> packages;
    int good_files = 0;
    int bad_files = 0;
    size_t total_size = 0;
    size_t size_done = 0;
    bool prev_print = false;

    std::ifstream mirror_config_file(mirror_file);
    if (!mirror_config_file) {
        throw std::runtime_error("Failed to read mirror config file: " + mirror_file);
    }

    bool safe_mode = false;
    bool verbose = false;
    bool bad_lock = false;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--safe") == 0) {
            safe_mode = true;
        } else if (std::strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (std::strcmp(argv[i], "--bad-lock") == 0){
            bad_lock = true;
        }
    }

    std::string line;
    while (std::getline(mirror_config_file, line)) {
        std::istringstream line_stream(line);
        std::string token;
        line_stream >> token;
        if (token == "set") {
            std::string param;
            line_stream >> param;
            if (param == "base_path") {
                std::string base_path;
                line_stream >> base_path;
                repo_path = base_path + "/mirror/";
                if (bad_lock){
                    lock_file = "./apt-mirror.lock";
                }else{
                    lock_file = base_path + "/var/apt-mirror.lock";
                }

            }
        } else if (token == "deb") {
            std::string distro;
            if (!repo_updated) {
                std::string repo;
                line_stream >> ignore >> repo;
                size_t protocol_pos = repo.find("://");
                if (protocol_pos != std::string::npos) {
                    repo_path += repo.substr(protocol_pos + 3);
                } else {
                    repo_path += repo;
                }
                server = repo;
                repo_updated = true;
                line_stream >> distro;
            }else{
                line_stream >> ignore >> ignore >> distro;
            }
            if (std::find(distros.begin(), distros.end(), distro) == distros.end()) {
                distros.push_back(distro);
            }
        }
    }

    int lock_file_file = open(lock_file.c_str(), O_CREAT|O_RDONLY,0666);
    if (lock_file_file == -1){
        std::cerr << "Error opening lock file: " << lock_file << '\n';
        std::cerr << strerror(errno) << '\n';
        return 1;
    }
    while (true) {
        try {
            if (flock(lock_file_file, LOCK_EX | LOCK_NB) == 0) {
                std::cout << "Got lock!" << '\n';
                break;
            }
        } catch (const std::exception& e) {
            std::cout << "Failed to get lock, retrying in 2 minutes..." << '\n';
            sleep(120);
        }
    }
    int count = 0;
    {
        std::cout << "Indexing..." << '\n';
        std::string e_name;
        std::string e_hash;
        std::string e_size;
        std::string curr_file;
        std::string token;
        std::string mirror_content;
        std::string entry;
        size_t start;
        std::istringstream entry_stream;
        std::istringstream line_stream;
        auto start_time = std::chrono::high_resolution_clock::now();
        for (const auto &distro: distros) {
            for (const auto &distro2: distros2) {
                for (const auto &arch: archs) {
                    curr_file = repo_path + std::string("/dists/").append(distro).append("/").append(distro2).append(
                            "/binary-").append(arch).append("/Packages");
                    if (access(curr_file.c_str(), F_OK) != -1) {
                        mirror_content = get_file_contents(curr_file);
                        start = 0;
                        while (get_next(mirror_content, start, entry, "\n\n")) {
                            count++;
                            entry_stream = std::istringstream (entry);
                            while (std::getline(entry_stream, line)) {
                                line_stream = std::istringstream (line);
                                line_stream >> token;
                                if (token == "Filename:") {
                                    line_stream >> e_name;
                                } else if (token == "Size:") {
                                    line_stream >> e_size;
                                } else if (token == "SHA256:") {
                                    line_stream >> e_hash;
                                    break;
                                }
                            }
                            if (!e_name.empty() && !e_hash.empty() && !e_size.empty() &&
                                packages.find(e_name) == packages.end()) {
                                packages[e_name] = std::make_pair(e_hash, std::stoul(e_size));
                            }
                        }
                    }
                }
            }
        }
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        std::cout << "Done Indexing! ";
        if (duration.count() < 1000) {
            std::cout << "Elapsed Time: " << duration.count() << " milliseconds\n";
        } else if (duration.count() < 60*1000) {
            std::cout << "Elapsed Time: " << std::fixed << std::setprecision(2) << duration.count() / 1000.0 << " seconds\n";
        } else if (duration.count() < 60*60*1000){
            std::cout << "Elapsed Time: " << std::fixed << std::setprecision(2) << duration.count() / 60'000.0 << " minutes\n";
        } else{
            std::cout << "Elapsed Time: " << (int) (duration.count()/(60.0*60*1000)) << " hours " << (int) (duration.count()/(60*1000)) % 60 <<" minutes}\n";
        }
    }
    for (const auto& package : packages) {
        total_size += package.second.second;
    }
    std::cout << "Verifying " << count << " packages (" << format_file_size(total_size) << ")..." << '\n';
    if (verbose){
        std::cout << '\n';
    }
    auto start_time = std::chrono::high_resolution_clock::now();
    walk_directory(repo_path+"/pool/", total_size,safe_mode, verbose, repo_path, packages, good_files, bad_files,
                   size_done, prev_print, server, start_time);
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    std::cout << "Done checking repository." << '\n';
    if (duration.count() < 1000) {
        std::cout << "Elapsed Time: " << duration.count() << " milliseconds\n";
    } else if (duration.count() < 60000) {
        std::cout << "Elapsed Time: " << std::fixed << std::setprecision(2) << duration.count() / 1000.0 << " seconds\n";
    } else if (duration.count() < 60*60*1000){
        std::cout << "Elapsed Time: " << std::fixed << std::setprecision(2) << duration.count() / 60'000.0 << " minutes\n";
    } else{
        std::cout << "Elapsed Time: " << (int) (duration.count()/(60.0*60*1000)) << " hours " << (int) (duration.count()/(60*1000)) % 60 <<" minutes}\n";
    }

    std::cout << "\nSUMMARY:" << '\n';
    std::cout << "Good files: " << good_files << '\n';
    std::cout << "Bad files: " << bad_files << '\n';
    if (good_files + bad_files > 0) {
        double success_rate = static_cast<double>(good_files) / (good_files + bad_files) * 100.0;
        std::cout << "Success rate: " << std::fixed << std::setprecision(2) << success_rate << "%" << '\n';
    }

    if (flock(lock_file_file, LOCK_UN) != 0) {
        std::cout << "Failed to release lock!" << '\n';
    }
    close(lock_file_file);
    unlink(lock_file.c_str());

    return 0;
}
