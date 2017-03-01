#ifndef HOSTSFILE_H
#define HOSTSFILE_H

#include <string>
#include <sqlite++/db.hpp>

class HostsFile: private SQLite::DB
{
public:
    HostsFile();
    ~HostsFile();

    void saveToFile(const std::string &loc);
    void insert(const std::string &ip, const std::string &hostname);
    void replace(const std::string &ip, const std::string &hostname);
    void remove(const std::string &hostname);
};

#endif // HOSTSFILE_H
