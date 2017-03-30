#include <iostream>
#include <cstdio>
#include <regex>
#include <fstream>
#include <sqlite++/db.hpp>
#include <sqlite++/exception.hpp>
#include <curl/curl.h>
#include "config.h"
#include "hostsfile.h"

/*
 * Also: Custom config db, verbose, disable whitelist/blacklist/redirect
 */
static const std::string ARG_ALLOW_REDIR{"--allow-redirection"};
static const std::string ARG_REDIR_IP{"--redirect-ip"};
static const std::string ARG_OUT_FILE{"--out"};
static const std::string ARG_HELP{"--help"};
static const std::string ARG_RESET{"--reset"};
static const std::string ARG_ENABLE{"--enable"};
static const std::string ARG_DISABLE{"--disable"};
static const std::string ARG_WHITELIST{"--whitelist"};
static const std::string ARG_BLACKLIST{"--blacklist"};
static const std::string ARG_REDIRECT{"--redirect"};
static const std::string ARG_HOSTS_SRC{"--hosts-src"};
static const std::string ARG_ADD{"--add"};
static const std::string ARG_REMOVE{"--remove"};

static const std::string dbFileName{"config.db"};
static const std::string redirectIPParam{"[IP_ADDRESS]"};

void printHelp(char *exeName) {
    std::cout << "Usage: " << exeName << " [CONFIG] [...]\n" <<
                 "\n" <<
                 ARG_ALLOW_REDIR << " Allow redirection entries from downloaded hosts files.\n" <<
                 ARG_REDIR_IP << " [IP_ADDRESS] Use the provided IP address for blacklist entries.\n" <<
                 std::string(ARG_REDIR_IP.length() + 14, ' ') << "If omitted, defaults to 127.0.0.1.\n" <<
                 ARG_OUT_FILE << " [FILE] Generate a hosts file and output to this location.\n" <<
                 ARG_RESET << " Reset the configuration database to default.\n" <<
                 ARG_ADD << " [OPTION] [ARG] [...] Add the following entries to the configuration database (default).\n" <<
                 ARG_REMOVE << " [OPTION] [ARG] [...] Remove the following entries from the configuration database.\n" <<
                 ARG_ENABLE << " [OPTION] [INDEX] Enable the following item by index number, if disabled.\n" <<
                 ARG_DISABLE << " [OPTION] [INDEX] Disable the following item by index number, if enabled.\n" <<
                 ARG_HELP << " Display this help and exit.\n" <<
                 "\n[OPTIONS]\n" <<
                 "Each of the following options specify behavior that is saved in the configuration database.\n" <<
                 "and will persist across calls to " << exeName << ".\n" <<
                 "Whether the option is added or removed is determined by whether " << ARG_ADD << " or " << ARG_REMOVE << "\n" <<
                 "is nearest to the left of the option.\n\n" <<
                 ARG_BLACKLIST << " [DOMAIN] (Un)blacklist the given domain.\n" <<
                 ARG_WHITELIST << " [DOMAIN] (Un)whitelist the given domain (Prevents the domain from being blocked).\n" <<
                 ARG_REDIRECT << " (with " + ARG_ADD + ") [DOMAIN] [IP_ADDRESS] Redirect the given domain to the given IP address.\n" <<
                 std::string(ARG_REDIRECT.length(), ' ') << " (with " + ARG_REMOVE + ") [DOMAIN] Remove the redirection for the given domain.\n" <<
                 ARG_HOSTS_SRC << " [URL] Download a hosts file from the given URL.\n" <<
                 "\n" <<
                 "Full documentation: https://shadow53.com/hosts-editor/" << std::endl;
    std::exit(0); // Cleans up
}

bool configure(Config &config, int argc, char *argv[]) {
    try {
        config.prepare();
        if (argc > 1) {
            bool removing{false};
            std::string arg;
            for (int i = 1; i < argc; ++i) {
                arg = argv[i];
                if (arg == ARG_ALLOW_REDIR)
                    config.allowHostsRedirection(true);
                else if(arg == ARG_REDIR_IP) {
                    if (i+1 < argc) {
                        arg = argv[++i];
                        if (std::regex_match(arg, Config::ipRegex))
                            config.setRedirectIP(arg);
                        else
                            throw std::invalid_argument(arg + " is not a valid IP address!");
                    }
                    else throw std::invalid_argument("Missing argument [IP_ADDRESS] to flag " + ARG_REDIR_IP);
                }
                else if (arg == ARG_RESET) {
                    config.resetDB();
                }
                else if (arg == ARG_REMOVE) {
                    removing = true;
                }
                else if (arg == ARG_ADD) {
                    removing = false;
                }
                else if (arg == ARG_ENABLE || arg == ARG_DISABLE) {
                    if (i+2 < argc) {
                        std::string option = argv[++i];
                        std::string optionArg = argv[++i];

                        if (option == ARG_HOSTS_SRC) {
                            int index;
                            try {
                                index = std::stoi(optionArg);
                            }
                            catch (std::invalid_argument &e) {
                                throw std::invalid_argument("Could not convert \"" + optionArg + "\" to an index number");
                            }
                            config.toggleHostsSource(index, arg == ARG_ENABLE);
                        }
                        else if (option == ARG_BLACKLIST) config.toggleBlacklist(optionArg, arg == ARG_ENABLE);
                        else if (option == ARG_WHITELIST) config.toggleWhitelist(optionArg, arg == ARG_ENABLE);
                        else if (option == ARG_REDIRECT) config.toggleRedirect(optionArg, arg == ARG_ENABLE);

                    }
                    else throw std::invalid_argument("Missing one or more of arguments [OPTION] [INDEX] to flag " + arg);
                }
                else if (arg == ARG_BLACKLIST) {
                    if (i+1 < argc) {
                        arg = argv[++i];
                        if (removing) {
                            config.rmBlacklist(arg);
                        }
                        else {
                            if (std::regex_match(arg, Config::domainRegex))
                                config.blacklist(arg);
                            else
                                throw std::invalid_argument(arg + " is not a valid domain name!");
                        }

                    }
                    else throw std::invalid_argument("Missing argument [DOMAIN] to flag " + ARG_BLACKLIST);
                }
                else if (arg == ARG_WHITELIST) {
                    if (i+1 < argc) {
                        arg = argv[++i];
                        if (removing) {
                            config.rmWhitelist(arg);
                        }
                        else {
                            if (std::regex_match(arg, Config::domainRegex))
                                config.whitelist(arg);
                            else
                                throw std::invalid_argument(arg + " is not a valid domain name!");
                        }

                    }
                    else throw std::invalid_argument("Missing argument [DOMAIN] to flag " + ARG_WHITELIST);
                }
                else if (arg == ARG_REDIRECT) {
                    if (removing) {
                        if (i+1 < argc) {
                            arg = argv[++i];
                            config.rmRedirect(arg);
                        }
                        else throw std::invalid_argument("Missing argument [DOMAIN] to flags " + ARG_REMOVE + " " + ARG_REDIRECT);
                    }
                    else {
                        if (i+2 < argc) {
                            std::string domain, ip;
                            domain = argv[++i];
                            ip = argv[++i];
                            if (!std::regex_match(domain, Config::domainRegex))
                                throw std::invalid_argument(domain + " is not a valid domain name!");
                            else if (!std::regex_match(ip, Config::ipRegex))
                                throw std::invalid_argument(ip + " is not a valid IP address!");
                            else
                                config.redirect(domain, ip);
                        }
                        else throw std::invalid_argument("Missing one or more of arguments [DOMAIN] [IP_ADDRESS] to flag " + ARG_REDIRECT);
                    }
                }
                else if (arg == ARG_HOSTS_SRC) {
                    if (i+1 < argc) {
                        arg = argv[++i];
                        if (removing) {
                            config.rmHostsSrc(arg);
                        }
                        else {
                            if (std::regex_match(arg, Config::urlRegex))
                                config.addHostsSrc(arg);
                            else
                                throw std::invalid_argument(arg + " is not a valid HTTPS URL!");
                        }
                    }
                    else throw std::invalid_argument("Missing argument [URL] to flag " + ARG_HOSTS_SRC);
                }
                else if (arg == ARG_OUT_FILE) {
                    if (i+1 < argc) {
                        arg = argv[++i];
                        config.outFile(arg);
                        // TODO: Check if valid file, can write, etc?
                    }
                    else throw std::invalid_argument("Missing argument [FILE] to flag " + ARG_OUT_FILE);
                }
                else if (arg == ARG_HELP) {
                    printHelp(argv[0]);
                }
            }
        }

        config.configure();
        return true;
    }
    catch (SQLite::except::Readonly &e) {
        std::cerr << "Could not modify the configuration database.\n"
                  << "Do you have the necessary permissions?\n"
                  << "Error: " << e.what() << std::endl;
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

    try {
        if (!configure(config, argc, argv)) return EXIT_FAILURE;
    }
    catch(std::invalid_argument &e) {
        std::cout << e.what() << std::endl;
        std::exit(EXIT_FAILURE);
    }

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

    try {
        SQLite::DB::copy(config.m_db, configDB);
    }
    catch (SQLite::except::Readonly &e) {
        std::cerr << "Could not modify the configuration database.\n"
                  << "Do you have the necessary permissions?\n"
                  << "Error: " << e.what() << std::endl;
    }

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
