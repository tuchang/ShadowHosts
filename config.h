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
        static const std::string allowRedirectArg;
        static const std::string redirectIPArg;
        static const std::string helpArg;
        static const std::string resetArg;
        static const std::string outFileArg;

        static const std::string DEFAULT_IP;

        static const std::string HOSTS_TABLE;
        static const std::string CONFIG_TABLE;
        static const std::string BLACKLIST_TABLE;
        static const std::string WHITELIST_TABLE;
        static const std::string REDIRECT_TABLE;
        static const std::string ENTRIES_TABLE;

        std::vector<std::string> m_hostURLs;

        bool allowRedirectionInHosts{false};
        std::string redirectIP{DEFAULT_IP};

        std::string m_outFile{"/etc/hosts"};

        bool m_isHelp{false};
        bool m_resetDB{false};

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

        const std::string& getRedirectIP() const;
        bool wantsHelp() const;
        bool wantsResetDB() const;
        void resetDB();

        void insertEntry(const std::string &host, const std::string &line);
        void saveToFile();

        static const std::regex ipRegex;
        static const std::regex domainRegex;
        static const std::regex urlRegex;

        SQLite::DB m_db;
};

#endif // SETUP_H
