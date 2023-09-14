#include "print.h"
#include "apt_mirror_tools.h"

void inline print_help(){
    print::print(R"(Usage: apt-mirror-tools [options] <operation>
Options:
    -s, --safe-mode     Run in safe mode. This will not change any files.
    -v, --verbose       Print verbose output.
    -b, --bad-lock      Ignore lock file errors. This may cause data corruption.
    -t, --threads       Set the number of threads to use. Default: 1
    -h, --help          Print this help message.
Operations:
    mirror              Update a repository. (Download new files and remove old ones)
    verify              Verify a repository. (Check for wrong files and missing files)
    clean               Clean a repository. (Remove wrong files and ghost files)
)");
}

apt_mirror_tools::settings_struct parse_arguments(int argc, char** argv){
    apt_mirror_tools::settings_struct settings{};
    settings.safe_mode = false;
    settings.verbose = false;
    settings.bad_lock = false;
    settings.threads = 1;
    settings.op = apt_mirror_tools::operation::invalid;
    for (int i = 1; i < argc-1; i++){
        std::string arg = argv[i];
        if (arg == "-s" || arg == "--safe-mode"){
            settings.safe_mode = true;
        } else if (arg == "-v" || arg == "--verbose"){
            settings.verbose = true;
        } else if (arg == "-b" || arg == "--bad-lock"){
            settings.bad_lock = true;
        } else if (arg == "-h" || arg == "--help"){
            print_help();
            exit(0);
        } else if (arg == "-t" || arg == "--threads"){
            if (i + 1 >= argc){
                print_help();
                throw std::runtime_error("Missing argument for: " + arg);
            }
            try {
                settings.threads = std::stoi(argv[++i]);
            } catch (std::exception& e){
                print_help();
                throw std::runtime_error("Invalid argument for: " + arg);
            }
        } else {
            print_help();
            throw std::runtime_error("Unknown argument: " + arg);
        }
    }
    if (argc < 2){
        print_help();
        throw std::runtime_error("Missing operation");
    }
    std::string op = argv[argc-1];
    if (op == "mirror"){
        settings.op = apt_mirror_tools::operation::mirror;
    } else if (op == "verify"){
        settings.op = apt_mirror_tools::operation::verify;
    } else if (op == "clean"){
        settings.op = apt_mirror_tools::operation::clean;
    } else {
        print_help();
        throw std::runtime_error("Unknown operation: " + op);
    }
    return settings;
}

int main(int argc, char** argv) {
    apt_mirror_tools::settings_struct settings = parse_arguments(argc, argv);
    apt_mirror_tools tools(settings);
    return 0;
}