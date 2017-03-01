#include <string>
#include <sqlite++/stmt.hpp>
#include <sqlite++/row.hpp>
#include <sqlite++/exception.hpp>
#include "config.h"

const std::regex Config::ipRegex{"^([01]?\\d\\d?|2[0-4]\\d|25[0-5])(\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])){3}$",
                            std::regex::ECMAScript | std::regex::optimize};
const std::regex Config::domainRegex{"^(([a-zA-Z0-9\\-])+\\.)*([a-z]){2,}$",
                            std::regex::ECMAScript | std::regex::optimize};
const std::regex Config::urlRegex{"https:\\/\\/((\\w|-)+)?(\\.(\\w|-)+)*"
                            "(\\/(\\w|_|-|.|~|(%(2[1346789ABCF]|3[ABDF]|40|5[BD])))*)*"
                            "(\\?((\\w|_|-|.|~|(%(2[1346789ABCF]|3[ABDF]|40|5[BD])))*"
                            "=(\\w|_|-|.|~|(%(2[1346789ABCF]|3[ABDF]|40|5[BD])))*)"
                            "(&(?=(\\w|_|-|.|~|(%(2[1346789ABCF]|3[ABDF]|40|5[BD])))*"
                            "=(\\w|_|-|.|~|(%(2[1346789ABCF]|3[ABDF]|40|5[BD])))))*)?",
                            std::regex::ECMAScript | std::regex::optimize};

const std::string Config::allowRedirectArg{"--allow-redirection"};
const std::string Config::redirectIPArg{"--redirect-ip"};
const std::string Config::outFileArg{"--out"};
const std::string Config::helpArg{"--help"};
const std::string Config::resetArg{"--reset"};

const std::string Config::DEFAULT_IP{"127.0.0.1"};

const std::string Config::HOSTS_TABLE{"hosts"};
const std::string Config::CONFIG_TABLE{"config"};
const std::string Config::BLACKLIST_TABLE{"blacklist"};
const std::string Config::WHITELIST_TABLE{"whitelist"};
const std::string Config::REDIRECT_TABLE{"redirect"};
const std::string Config::ENTRIES_TABLE{"entries"};

static const std::string WHITESPACE{" \t\r\n"};

Config::Config(const std::string &file): m_db{file} {
    m_db.open();
}

Config::~Config() { m_db.close(); }

void Config::prepareDB(SQLite::DB &db) {
    std::string statement{"CREATE TABLE IF NOT EXISTS " + CONFIG_TABLE + "("
                            "option_name TEXT NOT NULL PRIMARY KEY UNIQUE, "
                            "value TEXT NOT NULL"
                            ")"};
    m_db.execute(statement);
    statement = "CREATE TABLE IF NOT EXISTS " + HOSTS_TABLE + "("
                   "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                   "url TEXT NOT NULL UNIQUE, "
                   "enabled INT NOT NULL DEFAULT 1 CHECK(enabled IN(0, 1))"
                   ")";
    m_db.execute(statement);
    statement = "CREATE TABLE IF NOT EXISTS " + BLACKLIST_TABLE + "("
                   "domain TEXT NOT NULL PRIMARY KEY UNIQUE CHECK(domain IS NOT 'localhost'), "
                   "enabled INT NOT NULL DEFAULT 1 CHECK(enabled IN(0, 1))"
                   ")";
    m_db.execute(statement);
    statement = "CREATE TABLE IF NOT EXISTS " + WHITELIST_TABLE + "("
                   "domain TEXT NOT NULL PRIMARY KEY UNIQUE CHECK(domain IS NOT 'localhost'), "
                   "enabled INT NOT NULL DEFAULT 1 CHECK(enabled IN(0, 1))"
                   ")";
    m_db.execute(statement);
    statement = "CREATE TABLE IF NOT EXISTS " + REDIRECT_TABLE + "("
                   "domain TEXT NOT NULL PRIMARY KEY UNIQUE CHECK(domain IS NOT 'localhost'), "
                   "ip TEXT NOT NULL, "
                   "enabled INT NOT NULL DEFAULT 1 CHECK(enabled IN(0, 1))"
                   ")";
    m_db.execute(statement);
    statement = "CREATE TABLE IF NOT EXISTS " + ENTRIES_TABLE + "("
                   "source INT NOT NULL, "
                   "domain TEXT NOT NULL PRIMARY KEY UNIQUE CHECK(domain IS NOT 'localhost'), "
                   "ip TEXT NOT NULL, "
                   "enabled INT NOT NULL DEFAULT 1 CHECK(enabled IN(0, 1)), "
                   "FOREIGN KEY(source) REFERENCES " + HOSTS_TABLE + "(id)"
                   ")";
    m_db.execute(statement);

    SQLite::Stmt countHosts = m_db.prepare("SELECT COUNT(*) FROM " + HOSTS_TABLE);
    int count;
    countHosts.exec([&count](SQLite::Row &row) mutable -> void {
       count = row.getInt(0);
    });

    if (count == 0) resetDB();
}

void Config::parseArgs(int argc, char *argv[]) {
    if (argc > 1) {
        std::string arg;
        for (int i = 1; i < argc; ++i) {
            arg = argv[i];
            if (arg == allowRedirectArg)
                allowRedirectionInHosts = true;
            else if(arg == redirectIPArg) {
                if (i+1 < argc) {
                    arg = argv[++i];
                    if (std::regex_match(arg, Config::ipRegex))
                        redirectIP = arg;
                    else
                        throw std::invalid_argument(arg + " is not a valid IP address!");
                }
                else throw std::invalid_argument("Missing argument [IP_ADDRESS] to flag " + redirectIPArg);
            }
            else if (arg == resetArg) {
                m_resetDB = true;
            }
            else if (arg == outFileArg) {
                if (i+1 < argc) {
                    arg = argv[++i];
                    m_outFile = arg;
                    // TODO: Check if valid file, can write, etc?
                }
                else throw std::invalid_argument("Missing argument [IP_ADDRESS] to flag " + redirectIPArg);
            }
            else if (arg == helpArg) {
                m_isHelp = true;
                break;
            }
        }
    }
}


void Config::configure(int argc, char **argv) {
    prepareDB(m_db);
    parseArgs(argc, argv);
    if (wantsResetDB()) {
        resetDB();
    }
    SQLite::Stmt urls = m_db.prepare("SELECT url FROM " + HOSTS_TABLE + " WHERE enabled = 1");
    std::string url;
    urls.exec([this, &url](SQLite::Row &row) mutable -> void {
        url = row.getString(0);
        if (std::regex_match(url, this->urlRegex))
            this->m_hostURLs.emplace_back(url);
    });
}

const std::vector<std::string>& Config::getHostUrls() { return m_hostURLs; }
const std::string& Config::getHelpFlag() { return helpArg; }
const std::string& Config::getRedirectIPFlag() { return redirectIPArg; }
const std::string& Config::getAllowRedirectFlag() { return allowRedirectArg; }
const std::string& Config::getOutFileFlag() { return outFileArg; }
const std::string& Config::getResetDBFlag() { return resetArg; }

const std::string& Config::getRedirectIP() const { return redirectIP; }
bool Config::wantsHelp() const { return m_isHelp; }
bool Config::wantsResetDB() const { return m_resetDB; }

void Config::saveToFile() {
    std::string ip, domain;
    HostsFile hosts;

    SQLite::Stmt save = m_db.prepare("SELECT ip, domain FROM " + ENTRIES_TABLE + " WHERE enabled = 1");
    save.exec([this, &hosts, &ip, &domain](SQLite::Row &row) mutable -> void {
        ip = row.getString(0);
        domain = row.getString(1);

        if ((ip == DEFAULT_IP || allowRedirectionInHosts) && std::regex_match(ip, ipRegex) && std::regex_match(domain, domainRegex)) {
            hosts.insert((ip == DEFAULT_IP ? redirectIP : ip), domain);
        }
    });

    SQLite::Stmt blacklist = m_db.prepare("SELECT domain FROM " + BLACKLIST_TABLE + " WHERE enabled = 1");
    blacklist.exec([this, &hosts, &domain](SQLite::Row &row) mutable -> void {
        domain = row.getString(0);

        if (std::regex_match(domain, domainRegex)) {
            hosts.insert(redirectIP, domain);
        }
    });

    SQLite::Stmt whitelist = m_db.prepare("SELECT domain FROM " + WHITELIST_TABLE + " WHERE enabled = 1");
    whitelist.exec([this, &hosts, &domain](SQLite::Row &row) mutable -> void {
        domain = row.getString(0);

        if (std::regex_match(domain, domainRegex)) {
            hosts.insert(DEFAULT_IP, domain);
        }
    });

    SQLite::Stmt redirect = m_db.prepare("SELECT ip, domain FROM " + REDIRECT_TABLE + " WHERE enabled = 1");
    redirect.exec([this, &hosts, &ip, &domain](SQLite::Row &row) mutable -> void {
        ip = row.getString(0);
        domain = row.getString(1);

        if (std::regex_match(ip, ipRegex) && std::regex_match(domain, domainRegex)) {
            hosts.insert(ip, domain);
        }
    });

    hosts.saveToFile(m_outFile);
}

void Config::resetDB() {
    m_db.execute("DELETE FROM " + CONFIG_TABLE);
    m_db.execute("DELETE FROM " + HOSTS_TABLE);
    m_db.execute("DELETE FROM " + WHITELIST_TABLE);
    m_db.execute("DELETE FROM " + BLACKLIST_TABLE);
    m_db.execute("DELETE FROM " + REDIRECT_TABLE);
    m_db.execute("DELETE FROM " + ENTRIES_TABLE);

    SQLite::Stmt insert = m_db.prepare("INSERT INTO " + HOSTS_TABLE + "(url) VALUES(:url)");
    std::string host = "https://adaway.org/hosts.txt";
    insert.bindValue(":url", host);
    insert.exec();

    insert.clearBindings();
    host = "https://hosts-file.net/ad_servers.txt";
    insert.bindValue(":url", host);
    insert.exec();

    insert.clearBindings();
    host = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext";
    insert.bindValue(":url", host);
    insert.exec();
}

void Config::insertEntry(const std::string &host, const std::string &line) {
    std::string domain;
    std::string ip;

    size_t start, end;
    start = line.find_first_not_of(WHITESPACE);
    if (start == std::string::npos || line[start] == '#') return;
    end = line.find_first_of(WHITESPACE, start);

    if (end == std::string::npos) return;
    ip = line.substr(start, end-start);

    if (!std::regex_match(ip, Config::ipRegex)) return;
    start = line.find_first_not_of(WHITESPACE, end);

    if (start == std::string::npos || line[start] == '#') return;
    end = line.find_first_of(WHITESPACE, start);
    domain = line.substr(start, end-start);

    if (domain == "localhost") return;
    if (!std::regex_match(domain, Config::domainRegex)) return;

    int id{0};
    try {
        SQLite::Stmt select = m_db.prepare("SELECT id FROM " + HOSTS_TABLE + " WHERE url = :host");
        select.bindValue(":host", host);

        select.exec([&id](SQLite::Row &row) mutable -> void {
            id = row.getInt(0);
        });
    }
    catch(SQLite::except::SQLiteError &e) {
        // What would be here?
    }

    if (id > 0) {
        try {
            SQLite::Stmt insert = m_db.prepare("INSERT INTO " + ENTRIES_TABLE +
                                                   "(source, domain, ip) VALUES(:src, :url, :ip)");
            insert.bindValue(":src", id);
            insert.bindValue(":url", domain);
            insert.bindValue(":ip", ip);
            insert.exec();
        }
        catch (SQLite::except::Constraint &e) {
            // Absorb unique/pkey failures: multiple host files may have the same entry multiple times
            if (!(e.unique() || e.primaryKey()))
                throw e;
        }
    }
}
