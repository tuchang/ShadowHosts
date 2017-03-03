#ifndef SETUP_H
#define SETUP_H
#include <vector>
#include <string>
#include <regex>
#include <sqlite++/db.hpp>
#include "hostsfile.h"

class Config {
    private:
        /*
         * Also: Custom config db, custom out file/stdout, verbose, reset, disable whitelist/blacklist/redirect
         */
        static const std::string ARG_ALLOW_REDIR;
        static const std::string ARG_REDIR_IP;
        static const std::string ARG_HELP;
        static const std::string ARG_RESET;
        static const std::string ARG_OUT_FILE;
        static const std::string ARG_WHITELIST;
        static const std::string ARG_BLACKLIST;
        static const std::string ARG_REDIRECT;
        static const std::string ARG_HOSTS_SRC;
        static const std::string ARG_REMOVE;
        static const std::string ARG_ADD;

        static const std::string DEFAULT_IP;

        static const std::string HOSTS_TABLE;
        static const std::string CONFIG_TABLE;
        static const std::string BLACKLIST_TABLE;
        static const std::string WHITELIST_TABLE;
        static const std::string REDIRECT_TABLE;
        static const std::string ENTRIES_TABLE;

        std::vector<std::string> m_hostURLs;

        bool m_allowRedirectionInHosts{false};
        bool m_isConfiguring{false};

        std::string m_redirectIP{DEFAULT_IP};

        std::string m_outFile;

        bool m_isHelp{false};
        bool m_resetDB{false};
        bool m_configOnly{false};
        bool m_removing{false};

        void parseArgs(int argc, char **argv);
        void prepareDB(SQLite::DB &db);
    public:
        Config(const std::string &file);
        ~Config();
        void configure(int argc, char **argv);
        const std::vector<std::string>& getHostUrls();
        static const std::string& getHelpFlag();
        static const std::string& getRedirectIPFlag();
        static const std::string& getAllowRedirectFlag();
        static const std::string& getOutFileFlag();
        static const std::string& getResetDBFlag();
        static const std::string& getBlacklistFlag();
        static const std::string& getWhitelistFlag();
        static const std::string& getRedirectionFlag();

        const std::string& getRedirectIP() const;
        bool wantsHelp() const;
        bool wantsResetDB() const;
        const std::string& outFile() const;
        void resetDB();

        void insertEntry(const std::string &host, const std::string &line);
        void saveToFile();
        void addHostsSrc(const std::string &url);
        void blacklist(const std::string &domain);
        void whitelist(const std::string &domain);
        void redirect(const std::string &domain, const std::string &ip);
        void rmBlacklist(const std::string &domain);
        void rmWhitelist(const std::string &domain);
        void rmRedirect(const std::string &domain);
        void rmHostsSrc(const std::string &domain);

        static const std::regex ipRegex;
        static const std::regex domainRegex;
        static const std::regex urlRegex;

        SQLite::DB m_db;
};

#endif // SETUP_H
