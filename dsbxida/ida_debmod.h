#pragma once

#include <deque>
#include <ida.hpp>
#include <idd.hpp>

//--------------------------------------------------------------------------
// Very simple class to store pending events
enum queue_pos_t
{
    IN_FRONT,
    IN_BACK
};

struct eventlist_t : public std::deque<debug_event_t>
{
private:
    bool synced;
public:
    // save a pending event
    void enqueue(const debug_event_t& ev, queue_pos_t pos)
    {
        if(pos != IN_BACK)
            push_front(ev);
        else
            push_back(ev);
    }

    // retrieve a pending event
    bool retrieve(debug_event_t* event)
    {
        if(empty())
            return false;
        // get the first event and return it
        *event = front();
        pop_front();
        return true;
    }
};
