//
// Created by corey on 10/12/24.
//

#ifndef MATRIXFORGE_ROOM_H
#define MATRIXFORGE_ROOM_H

#include <string>
#include <vector>
#include "Event.h"

class Room {
public:

    explicit Room(const std::string& id) :room_id(id) {}

    void add_event(const Event& event) { timeline_events.push_back(event); }
    void update_state(const Event& event) { state_events.push_back(event); }

    std::string room_id;
    std::vector<Event> timeline_events;
    std::vector<Event> state_events;
};

#endif //MATRIXFORGE_ROOM_H
