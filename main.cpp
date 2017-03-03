#include <iostream>
#include <cstdio>
#include <regex>
#include <fstream>
#include <sqlite++/db.hpp>
#include <sqlite++/exception.hpp>
#include <curl/curl.h>
#include "config.h"
#include "hostsfile.h"

static const std::string dbFileName{"config.db"};
static const std::string redirectIPParam{"[IP_ADDRESS]"};

void printHelp(char *exeName, Config& config) {
    std::cout << "Usage: " << exeName << " [OPTIONS]\n"
                 "\n" <<
                 Config::getAllowRedirectFlag() << " Allow redirection entries from downloaded hosts files\n" <<
                 Config::getRedirectIPFlag() << " [IP_ADDRESS] Use the provided IP address for blacklist entries.\n" <<
                 std::string(Config::getRedirectIPFlag().length() + 15, ' ') << "If omitted, defaults to 127.0.0.1\n" <<
                 Config::getOutFileFlag() << " [FILE] Specify a path to output the hosts file to\n" <<
                 Config::getResetDBFlag() << " Reset the configuration database to default\n" <<
                 Config::getBlacklistFlag() << " [DOMAIN] Blacklist the given domain\n" <<
                 Config::getWhitelistFlag() << " [DOMAIN] Whitelist the given domain (Prevents the domain from being blocked)\n" <<
                 Config::getRedirectionFlag() << " [DOMAIN] [IP_ADDRESS] Redirect the given domain to the given IP address\n"
                 "--help Display this help and exit\n"
                 "\n"
                 "Full documentation: https://shadow53.com/hosts-editor/" << std::endl;
    std::exit(0); // Cleans up
}

bool configure(Config &config, int argc, char *argv[]) {
    try {
        config.configure(argc, argv);
        if (config.wantsHelp()) {
            printHelp(argv[0], config);
        }
        return true;
    }
    catch (SQLite::except::CantOpen &e) {
        std::cerr << "Could not open configuration database file.\n"
                  << "Error: " << e.what() << std::endl;
        return false;
    }
    catch (SQLite::except::Misuse &e) {
        std::cerr << e.what() << std::endl;
        return false;
    }
    catch (std::invalid_argument &e) {
        std::cout << argv[0] << ": " << e.what() << std::endl;
        std::cout << "Try '" << argv[0] << " --help' for more information." << std::endl;
        return false;
    }
    catch (std::runtime_error &e) {
        std::cerr << e.what() << std::endl;
        return false;
    }
}

int main(int argc, char *argv[])
{
    SQLite::DB configDB(dbFileName);
    Config config(":memory:");
    SQLite::DB::copy(configDB, config.m_db);

    if (!configure(config, argc, argv)) return EXIT_FAILURE;

    if (config.outFile() != "") {
        CURLcode result = curl_global_init(CURL_GLOBAL_DEFAULT);

        if (result != 0){
            std::cerr << "Failed to initialize libcurl" << std::endl;
            return EXIT_FAILURE;
        }
        else {
            CURL *curl = curl_easy_init();
            // Abort if the download speed is below 100 b/s for 10 seconds
            result = curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 100);
            result = curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 10);
            // Try to get the file's last updated time first
            result = curl_easy_setopt(curl, CURLOPT_FILETIME, 1);
            // Set a custom user agent to fool servers
            // result = curl_easy_setopt(curl, CURLOPT_USERAGENT, "User Agent");
            // Only allow protocol redirects on HTTP and HTTPS
            result = curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
            // Only allow HTTP(S) protocols
            result = curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
            // Default schemeless urls to https
            result = curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

            std::vector<std::string> hosts = config.getHostUrls();
            std::string fileName;
            std::string hostName;
            size_t start;
            size_t end;
            std::ifstream file;
            for (const std::string &host : hosts) {
                if (std::regex_match(host, Config::urlRegex)) {
                    // Find beginning of substring
                    start = host.find("https://");
                    if (start == std::string::npos) {
                        start = host.find("http://");
                        if (start == std::string::npos) {
                            start = 0;
                        }
                        else start = 7;
                    }
                    else start = 8;

                    // Find end of domain substring
                    end = host.find_first_of('/', start+1);
                    if (end == std::string::npos) {
                        // We want to get to the end if this is npos
                        // Leave it as npos, since that gives the end
                        end = host.find_first_of('?', start);
                    }

                    // Pull domain out
                    hostName = host.substr(start, end-start);
                    fileName = "/tmp/shadowhosts-" + hostName;
                    std::FILE *cfile = std::fopen(fileName.c_str(), "w");
                    if (std::ferror(cfile))
                        std::perror("Failed to open file");
                    curl_easy_setopt(curl, CURLOPT_WRITEDATA, cfile);

                    // Set URL for request
                    curl_easy_setopt(curl, CURLOPT_URL, host.c_str());
                    result = curl_easy_perform(curl);
                    std::fclose(cfile);

                    if (result == CURLE_OK) {
                        file.open(fileName);
                        if (!file.fail()) {
                            std::string line;
                            while(std::getline(file, line)) {
                                config.insertEntry(host, line);
                            }
                        }
                        file.close();
                    }
                }
            }

            curl_easy_cleanup(curl);
        }

        curl_global_cleanup();
    }

    SQLite::DB::copy(config.m_db, configDB);

    if (config.outFile() != "") {
        try {
            config.saveToFile();
        }
        catch (const std::invalid_argument &e) {
            std::cout << "Could not open the file " << e.what() << " for writing.\n"
                         "Please make sure that the parent directories exist and the file itself is writable" << std::endl;
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
