//
// Created by corey on 10/12/24.
//

#ifndef MATRIXFORGE_EVENT_H
#define MATRIXFORGE_EVENT_H

#include <string>
#include <boost/json.hpp>

class Event {
public:
    std::string event_id;
    std::string sender;
    std::string event_type;
    boost::json::object content;

    Event(const std::string& id, const std::string& type,
          const std::string& sender, boost::json::object content)
          : event_id(id), event_type(type), sender(sender), content(std::move(content)) {}

    bool is_encrypted() const {
        return event_type == "m.room.encrypted";
    }
};

#endif //MATRIXFORGE_EVENT_H
