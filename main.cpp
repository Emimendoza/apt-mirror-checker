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
#include <filesystem>
#include <array>
#include <lzma.h>
#include <sys/stat.h>
#include "src/print.h"

constexpr unsigned int PERMS = 0755;

struct CTX
{
	const size_t& size_total;
	const bool& safe_mode;
	const bool& fix_perms;
	const bool& verbose;
	const std::string& repo_path;
	const std::unordered_map<std::string, std::pair<std::string, size_t>>& packages;
	int& good_files;
	int& bad_files;
	int& zombie_files;
	size_t& size_done;
	bool& prev_print;
	const std::string& server;
	const std::chrono::time_point<std::chrono::system_clock>& start_time;
	std::vector<std::string_view>& zombie_files_list;
	EVP_MD_CTX *md_ctx;
	char* buffer;
	unsigned char* hash;
	unsigned int* hash_len;
	std::stringstream* actual_hash_stream;
};

void mkdir_p(const std::filesystem::path& path) {
	if (!std::filesystem::exists(path.parent_path())) {
		mkdir_p(path.parent_path());
	}
	if (!std::filesystem::exists(path)) {
		print::raw_print("Creating directory: {}\n", path.string());
		std::filesystem::create_directory(path, path.parent_path());
	}
}

// Assumes file already exists
void fix_perms(const std::filesystem::path& path, const CTX& ctx) {
	if (!ctx.fix_perms)
		return;
	if (chmod(path.c_str(), PERMS) == -1) {
		throw std::runtime_error("Failed to fix permissions for file: " + path.string());
	}
}

constexpr size_t BUFFER_SIZE = 4194304; // 4 MB
constexpr unsigned char MAX_ERROR_DEPTH = 5;

template <typename CharT>
std::basic_istream<CharT>& ignore(std::basic_istream<CharT>& in){
    std::string ignoredValue;
    return in >> ignoredValue;
}

void inline print_help(){
    print::raw_print(R"(Usage: apt-mirror-checker [options]
This program checks the integrity of an apt-mirror repository.
It compares the hash of each file with the hash in the Packages file.
If the hash doesn't match, it marks the file as bad and downloads the correct version.
If the hash matches, it marks the file as good.
If the file is not in the Packages file, it marks the file as a zombie.


Options:
    --safe: Safe mode, will not download good versions of files
    --verbose: print out every file as it is checked
    --bad-lock: Use the bad lock file location (current working directory)
    --delete-zombies: Delete zombie files
    --store-zombies: Store zombie files in a file
	--fix-perms: Fix permissions of files (0755)
    --zombie-only: Only check for zombie files
    --algo2: Use the second algorithm for checking files (might be faster but ignores zombie files)
    --debug: Enable debug mode (implies --safe and --bad-lock)
    --help: print this help message
)");
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

std::string readXZFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for reading: " + filename);
    }

    // Set up the xz stream
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_stream_decoder(&strm, UINT64_MAX, 0);
    if (ret != LZMA_OK) {
        throw std::runtime_error("Failed to initialize xz decoder");
    }

    // Create an ostringstream to store the uncompressed data
    std::ostringstream oss;

    // Read and decompress the file
    constexpr size_t bufsize = 4096;
    char out_buffer[bufsize];
    char in_buffer[bufsize];
    strm.next_out = reinterpret_cast<uint8_t*>(out_buffer);
    strm.avail_out = bufsize;

    while (true) {
        auto action = LZMA_RUN;
        if (strm.avail_in == 0 && !file.eof()) {
            file.read(in_buffer, bufsize);
            strm.avail_in = file.gcount();
            strm.next_in = reinterpret_cast<uint8_t*>(in_buffer);
        }
        if (file.eof()){
            action = LZMA_FINISH;
        }

        ret = lzma_code(&strm, action);
        if (ret != LZMA_STREAM_END && ret != LZMA_OK) {
            lzma_end(&strm);
            throw std::runtime_error("Error decompressing data: " + std::to_string(ret));
        }
        if(strm.avail_out == 0 || ret == LZMA_STREAM_END) {
            oss.write(out_buffer, bufsize - strm.avail_out);
            strm.next_out = reinterpret_cast<uint8_t *>(out_buffer);
            strm.avail_out = bufsize;
        }
        if (ret == LZMA_STREAM_END)
            break;
    }

    // Clean up
    lzma_end(&strm);

    return oss.str();
}

std::string get_file_contents(const std::string& file_path) {
    if (file_path.ends_with(".xz")){
        return readXZFile(file_path);
    }
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


inline void print_status(const CTX& ctx)
{
    if (ctx.prev_print) {
        print::raw_print("\x1b[A\x1b[K");
    }
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - ctx.start_time);
    double rate = (ctx.size_done*1000.0)/duration.count();
    unsigned int seconds_total = (ctx.size_total)/rate;
    unsigned int seconds = duration.count()/1000;
    print::raw_print("{} | % Done: {:.2f}% | Good: {} | Bad: {} | Zombie:{} | % Good: {:.2f}% | {}/s | {:02}:{:02}:{:02}/{:02}:{:02}:{:02}\n",
               format_file_size(ctx.size_done),
               (double)(ctx.size_done * 100) / ctx.size_total,
               ctx.good_files,
               ctx.bad_files,
               ctx.zombie_files,
               (double)(ctx.good_files * 100) / (ctx.good_files + ctx.bad_files),
               format_file_size(rate),
               seconds / 3600,
               (seconds % 3600) / 60,
               seconds % 60,
               seconds_total / 3600,
               (seconds_total % 3600) / 60,
               seconds_total % 60);
    ctx.prev_print = true;
}

inline void download_file(const std::string& file_path, const std::string& download_url){
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
}
inline void get_sha256(const std::string& file_path, std::string& sum, const CTX& ctx){
    // Calculate the hash of the file
    EVP_MD_CTX_reset(ctx.md_ctx);

    if (EVP_DigestInit_ex(ctx.md_ctx, EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("Failed to initialize OpenSSL digest");
    }

    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + file_path);
    }

    size_t total_bytes_read = 0;

    while (file) {
        file.read(ctx.buffer, BUFFER_SIZE);
        size_t bytes_read = file.gcount();
        total_bytes_read += bytes_read;
        EVP_DigestUpdate(ctx.md_ctx, ctx.buffer, bytes_read);
    }

    file.close();

    if (total_bytes_read % BUFFER_SIZE == 0) {
        // Handle the case when the file size is exactly a multiple of the buffer size
        EVP_DigestUpdate(ctx.md_ctx, ctx.buffer, 0);
    }

    if (EVP_DigestFinal_ex(ctx.md_ctx, ctx.hash, ctx.hash_len) != 1) {
        EVP_MD_CTX_free(ctx.md_ctx);
        throw std::runtime_error("Failed to finalize OpenSSL digest");
    }

    for (unsigned int i = 0; i < *ctx.hash_len; i++) {
        (*ctx.actual_hash_stream) << std::setw(2) << static_cast<unsigned>(ctx.hash[i]);
    }
    sum = (*ctx.actual_hash_stream).str();
    (*ctx.actual_hash_stream).str("");
}

void check_file(const std::string &file_path, const CTX& ctx, const unsigned char& depth) {
    if (depth > MAX_ERROR_DEPTH)
    {
        throw std::runtime_error("Max error depth exceeded: This could be caused by the downloaded file hash not "
                                 "matching the expected hash too many times or by too many errors while downloading a file.\n");
    }
    size_t file_size = 0;
    try {
        std::string_view relative_file(file_path);
        relative_file.remove_prefix(ctx.repo_path.length() + 1);

        // Calculate the hash of the file
        std::string actual_hash;
        get_sha256(file_path, actual_hash, ctx);

        auto file_info_iter = ctx.packages.find(std::string(relative_file));
        if (file_info_iter != ctx.packages.end()) {
            const auto &file_info = file_info_iter->second;
            const std::string &expected_hash = file_info.first;
            file_size = file_info.second;
            if (actual_hash != expected_hash) {
                if (depth==0){
                    ctx.bad_files++;
                }
                ctx.prev_print = false;
                print::raw_print("\x1b[A[BAD FILE] {} - actual hash: {}, expected hash: {}\n", relative_file, actual_hash, expected_hash);
                if (!ctx.safe_mode) {
                    print::raw_print("Downloading good version of {}...\n", file_path);

                    // Remove the existing file
                    if (std::remove(file_path.c_str()) != 0) {
                        throw std::runtime_error("Error deleting file: " + file_path);
                    }

                    // Download the good version of the file
                    download_file(file_path, ctx.server + "/ubuntu/" + file_info_iter->first);
                    // Verify that the downloaded file is correct
                    check_file(file_path, ctx,depth+1);
                }
            } else if (ctx.verbose) {
                print::raw_print("\x1b[A[GOOD FILE] {} - hash: {}\n", relative_file, actual_hash);
                ctx.prev_print = false;
                if (depth == 0){
                    ctx.good_files++;
                }
            } else if (depth == 0) {
                ctx.good_files++;
            }
        } else {
            print::raw_print("\x1b[A[ZOMBIE FILE] {} - hash: {}\n", relative_file, actual_hash);
            ctx.zombie_files_list.push_back(relative_file);
            ctx.prev_print = false;
        }
        print_status(ctx);
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
        check_file(file_path, ctx,depth+1);
    }
    if (depth == 0){
        ctx.size_done += file_size;
    }
}

inline std::pair<bool, size_t> get_file_info(const std::string& file_name){
    struct stat buffer;
    int rc = stat(file_name.c_str(), &buffer);
    return std::make_pair(rc == 0, rc == 0 ? buffer.st_size : -1);
}


inline void check_file_2(const auto& package, const std::string& directoryPath, const CTX& ctx, const unsigned char& depth){
    const std::string file_path = directoryPath + package.first;
    if (depth > MAX_ERROR_DEPTH){
        throw std::runtime_error("Max error depth exceeded: This could be caused by the downloaded file hash not "
                                 "matching the expected hash too many times or by too many errors while downloading a file.\n");
    }
    try{
        const auto file_info = get_file_info(file_path);
        if (!file_info.first) {
            print::raw_print("\x1b[A[Missing File] {}\n", package.first);
            ctx.prev_print = false;
            // Download good version of the file
            if (!ctx.safe_mode) {
				mkdir_p(std::filesystem::path(file_path).parent_path());
                download_file(file_path, ctx.server + "/ubuntu/" + package.first);
                // Verify that the downloaded file is correct
                check_file_2(package, directoryPath, ctx, depth + 1);
            }
            if (depth == 0) {
                ctx.bad_files++;
                ctx.size_done += package.second.second;
                print_status(ctx);
            }
        } else if (file_info.second != package.second.second) {
            ctx.prev_print = false;
            print::raw_print("\x1b[A[BAD FILE] {} - actual size: {}, expected size: {}\n", package.first, file_info.second, package.second.second);
            if (!ctx.safe_mode) {
                print::raw_print("Downloading good version of {}...\n", file_path);

                // Remove the existing file
                if (std::remove(file_path.c_str()) != 0) {
                    throw std::runtime_error("Error deleting file: " + file_path);
                }

                // Download the good version of the file
                download_file(file_path, ctx.server + "/ubuntu/" + package.first);
                // Verify that the downloaded file is correct
                check_file_2(package, directoryPath, ctx,depth+1);
            }
            if (depth == 0){
                ctx.bad_files++;
                ctx.size_done += package.second.second;
                print_status(ctx);
            }
        } else {
            std::string actual_hash;
            get_sha256(file_path, actual_hash, ctx);
            if (actual_hash != package.second.first){
                if (depth==0){
                    ctx.bad_files++;
                }
                ctx.prev_print = false;
                print::raw_print("\x1b[A[BAD FILE] {} - actual hash: {}, expected hash: {}\n", package.first, actual_hash, package.second.first);
                if (!ctx.safe_mode) {
                    print::raw_print("Downloading good version of {}...\n", file_path);

                    // Remove the existing file
                    if (std::remove(file_path.c_str()) != 0) {
                        throw std::runtime_error("Error deleting file: " + file_path);
                    }

                    // Download the good version of the file
                    download_file(file_path, ctx.server + "/ubuntu/" + package.first);
                    // Verify that the downloaded file is correct
                    check_file_2(package, directoryPath, ctx,depth+1);
                }
            } else {
				fix_perms(file_path, ctx);
				if (ctx.verbose) {
					print::raw_print("\x1b[A[GOOD FILE] {} - hash: {}\n", package.first, actual_hash);
					ctx.prev_print = false;
				}
				if (depth == 0){
					ctx.good_files++;
					ctx.size_done += package.second.second;
					print_status(ctx);
				}
			}
        }
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
        check_file_2(package, directoryPath, ctx,depth+1);
    }
}
void algo_2(const auto& packageVector,const std::string& directoryPath, const CTX& ctx){
    for (const auto& package : packageVector){
        check_file_2(package, directoryPath, ctx,0);
    }
}


void walk_directory(const std::string& directoryPath, const CTX& ctx)
{
    // Process the directory
    for (const auto& entry : std::filesystem::directory_iterator(directoryPath))
    {
        const auto& path = entry.path();
        if (std::filesystem::is_directory(path))
        {
            // Recursive call for subdirectories
            walk_directory(path.string(),ctx);
        }
        else if (std::filesystem::is_regular_file(path))
        {
            // Process regular files
            check_file(path.string(), ctx, 0);
        }
    }
}

void walk_zombie_only(const std::string& directoryPath, const CTX& ctx)
{
    for (const auto& entry : std::filesystem::directory_iterator(directoryPath))
    {
        const auto& path = entry.path();
        if (std::filesystem::is_directory(path))
        {
            // Recursive call for subdirectories
            walk_directory(path.string(),ctx);
        }
        else if (std::filesystem::is_regular_file(path))
        {
            std::string str = path.string();
            std::string_view relative_file(str);
            relative_file.remove_prefix(ctx.repo_path.length() + 1);
            auto file_info_iter = ctx.packages.find(std::string(relative_file));
            if (file_info_iter == ctx.packages.end()) {
                print::raw_print("\x1b[A[ZOMBIE FILE] {}\n", relative_file);
                ctx.zombie_files_list.push_back(relative_file);
                ctx.prev_print = false;
                ctx.zombie_files++;
            } else {
                const auto &file_info = file_info_iter->second;
                size_t file_size = file_info.second;
                ctx.good_files++;
                ctx.size_done += file_size;
                if (ctx.verbose)
                {
                    print::raw_print("\x1b[A[GOOD FILE] {}\n", relative_file);
                    ctx.prev_print = false;
                }
            }
            print_status(ctx);
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
    int zombie_files = 0;
    size_t total_size = 0;
    size_t size_done = 0;
    bool prev_print = false;
    bool delete_zombies = false;
    bool zombie_only = false;
    bool safe_mode = false;
    bool verbose = false;
    bool bad_lock = false;
    bool store_zombies = false;
    bool algo2 = false;
    bool debug_mode = false;
	bool fix_perms = false;

    std::ifstream mirror_config_file(mirror_file);
    if (!mirror_config_file) {
        throw std::runtime_error("Failed to read mirror config file: " + mirror_file);
    }

    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--safe") == 0) {
            safe_mode = true;
        } else if (std::strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (std::strcmp(argv[i], "--bad-lock") == 0){
            bad_lock = true;
        } else if (std::strcmp(argv[i], "--delete-zombies") == 0){
            delete_zombies = true;
        } else if (std::strcmp(argv[i], "--store-zombies")==0){
            store_zombies = true;
        } else if (std::strcmp(argv[i], "--zombie-only")==0) {
            zombie_only = true;
        } else if (std::strcmp(argv[i], "--algo2")==0) {
            algo2 = true;
        } else if (std::strcmp(argv[i], "--debug")==0) {
            debug_mode = true;
            safe_mode = true;
            bad_lock = true;
        } else if (std::strcmp(argv[i], "--help") == 0) {
			print_help();
			return 0;
		}else if (std::strcmp(argv[i], "--fix-perms")==0){
			fix_perms = true;
        } else {
            print::raw_print("Unknown option: {}\n", argv[i]);
            print_help();
            return 1;
        }
    }

    if((zombie_only || delete_zombies || store_zombies)&& algo2){
        print::raw_print("Options --zombie-only, --delete-zombies, and --store-zombies are incompatible with --algo2\n");
        return 1;
    }
	if(fix_perms && safe_mode){
		print::raw_print("Options --fix-perms and --safe are incompatible\n");
		return 1;
	}

    print::raw_print("Options used:\n");
    print::raw_print("Using a{} lock\n", (bad_lock ? " bad" : ""));
    print::raw_print("Being {}\n", (verbose ? "verbose" : "quiet"));
    print::raw_print("Safe mode: {}\n", (safe_mode ? "ON" : "OFF"));
    print::raw_print("Delete zombies: {}\n", (delete_zombies ? "ON" : "OFF"));
	print::raw_print("Fix permissions: {}\n", (fix_perms ? "ON" : "OFF"));
    print::raw_print("Store zombies: {}\n", (store_zombies ? "ON" : "OFF"));
    print::raw_print("Zombie only: {}\n", (zombie_only ? "ON" : "OFF"));
    print::raw_print("Using algorithm {}\n", (algo2 ? "2" : "1"));
    print::raw_print("Debug mode: {}\n", (debug_mode ? "ON" : "OFF"));
    print::raw_print("\n");


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
                print::raw_print("Got lock!\n");
                break;
            }
        } catch (const std::exception& e) {
            print::raw_print("Failed to get lock, retrying in 2 minutes...\n");
            sleep(120);
        }
    }
    int count = 0;
    {
        print::raw_print("Indexing...\n");
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
					if (exists(std::filesystem::path(curr_file))) {
					} else if (exists(std::filesystem::path(curr_file + ".xz"))) {
						curr_file.append(".xz");
					} else {
						continue;
					}
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
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        print::raw_print("Done Indexing! Elapsed Time: {:%H:%M:%S}\n", duration);
    }
    std::vector<std::pair<const std::string, std::pair<std::string, size_t>>> packagesVec;
    if (debug_mode){
        int i = 0;
        for (const auto& package : packages) {
            total_size += package.second.second;
            if(algo2){
                packagesVec.push_back(package);
            }
            if (i == 100){
                break;
            }
            i++;
        }
    } else{
        for (const auto& package : packages) {
            total_size += package.second.second;
            if(algo2){
                packagesVec.push_back(package);
            }
        }
    }
    print::raw_print("Verifying {} packages ({})...\n", count, format_file_size(total_size));
    if (verbose){
        print::raw_print("\n");
    }

    auto start_time = std::chrono::high_resolution_clock::now();
    std::vector<std::string_view> zombie_files_list;
    CTX ctx = {total_size, safe_mode, fix_perms, verbose, repo_path, packages, good_files, bad_files, zombie_files,
               size_done, prev_print, server, start_time, zombie_files_list, EVP_MD_CTX_new(), new char[BUFFER_SIZE],
               new unsigned char[EVP_MAX_MD_SIZE], new unsigned int, new std::stringstream};
    (*ctx.actual_hash_stream) << std::hex << std::setfill('0');
    if (!ctx.md_ctx){
        throw std::runtime_error("Failed to create OpenSSL context");
    }
    if (zombie_only){
        print::raw_print("Checking for zombie files...\n");
        walk_zombie_only(repo_path+"/pool/", ctx);
    } else if (!algo2) {
        walk_directory(repo_path+"/pool/", ctx);
    } else {
        algo_2(packagesVec, repo_path+"/", ctx);
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    delete[] ctx.hash;
    delete ctx.hash_len;
    delete ctx.actual_hash_stream;
    EVP_MD_CTX_free(ctx.md_ctx);
    delete[] ctx.buffer;

    print::raw_print("Done checking repository.\n");
    print::raw_print("Elapsed Time: {:%H:%M:%S}\n", duration);

    print::raw_print("\nSUMMARY:\n");
    print::raw_print("Good files: {}\n", good_files);
    print::raw_print("Bad files: {}\n", bad_files);
    if(!algo2) {
        print::raw_print("Zombie files: {}\n", zombie_files);
    }
    if (good_files + bad_files > 0) {
        double success_rate = static_cast<double>(good_files) / (good_files + bad_files) * 100.0;
        print::raw_print("Success rate: {:.2f}%\n\n", success_rate);
    }
    if (zombie_files > 0){
        print::raw_print("Zombie files:\n");
        for (const auto& zombie_file: zombie_files_list){
            if (delete_zombies){
                std::remove(((repo_path+"/pool/").append(zombie_file)).c_str());
                print::raw_print("Deleted {}\n", zombie_file);
            } else{
                print::raw_print("{}\n", zombie_file);
            }
        }
        if(store_zombies){
            std::ofstream zombie_file_file("zombie_files.txt", std::ios::app);
            for (const auto& zombie_file: zombie_files_list){
                zombie_file_file << (repo_path+"/pool/").append(zombie_file) << '\n';
            }
            zombie_file_file.close();
        }
    }

    if (flock(lock_file_file, LOCK_UN) != 0) {
        print::raw_print("Failed to release lock!\n");
    }
    close(lock_file_file);
    unlink(lock_file.c_str());

    return 0;
}
