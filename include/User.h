//
// Created by corey on 10/12/24.
//

#ifndef MATRIXFORGE_USER_H
#define MATRIXFORGE_USER_H

#include <string>

class User {
public:
    std::string user_id;
    std::string presence; // online, offline, etc.

    User(const std::string& id, const std::string& pres) : user_id(id), presence(pres) {}
};


#endif //MATRIXFORGE_USER_H
