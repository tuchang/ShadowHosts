#ifndef SETUP_H
#define SETUP_H
#include <vector>
#include <string>
#include <regex>
#include <sqlite++/db.hpp>
#include "hostsfile.h"

class Config {
    private:
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

        std::string m_outFile{""};

        bool m_configOnly{false};
        bool m_removing{false};

    public:
        Config(const std::string &file);
        ~Config();
        void prepare();
        void configure();
        const std::vector<std::string>& getHostUrls();

        const std::string& getRedirectIP() const;
        const std::string& outFile() const;
        void outFile(const std::string &file);
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

        void allowHostsRedirection(bool set);
        bool allowHostsRedirection() const;
        void setRedirectIP(const std::string &ip);

        static const std::regex ipRegex;
        static const std::regex domainRegex;
        static const std::regex urlRegex;

        SQLite::DB m_db;
};

#endif // SETUP_H
