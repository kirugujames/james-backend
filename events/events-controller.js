import connection from '../database/database.js';
import Events from './Models/Event.js';
import Event_Booking from './Models/Event-Booking.js';
import dotenv from 'dotenv';
dotenv.config();

//create event
export async function createEvent(req) {
    const {
        event_type,
        title,
        event_date,
        from_time,
        to_time,
        location,
        description,
        sub_title,
        image,
    } = req.body;
    try {
        const result = await Events.create({
            event_type,
            event_date,
            title,
            sub_title,
            location,
            from_time,
            to_time,
            description,
            image
        })
        console.log(result[0])
        return {
            message: "Event saved successfully",
            statusCode: 200,
            data: result
        }
    } catch (error) {

        return {
            message: error.message.split(":")[0],
            statusCode: 500,
            data: null
        }
    }

}
//get all  events
export async function getAllEvents() {
    try {
        const result = await Events.findAll()
        return {
            message: "Events fetched successfully",
            statusCode: 200,
            data: result
        }
    } catch (error) {
        return {
            message: error.message.split(":")[0],
            statusCode: 500,
            data: null
        }
    }
}
//get event by id
export async function getEventById(id) {
    try {
        const result = await Events.findByPk(id);
        return {
            message: "Events fetched successfully",
            statusCode: 200,
            data: result
        }
    } catch (error) {
        return {
            message: error.message.split(":")[0],
            statusCode: 500,
            data: null
        }
    }
}

//delete event 
export async function deleteEventById(id) {
    try {
        const event = await Events.findByPk(id);
        if (!event) return { message: "Event not found", data: null, statusCode: 404 };
        await event.destroy();
        return {
            message: "Event deleted successfully",
            statusCode: 200,
            data: event
        }
    } catch (error) {
        return {
            message: error.message.split(":")[0],
            statusCode: 500,
            data: null
        }
    }
}

//update event
export async function updateEvent(req) {
    try {
        const {
            id,
            event_type,
            title,
            event_date,
            from_time,
            to_time,
            location,
            description,
            sub_title,
            image } = req.body;

        const event = await Events.findByPk(id);
        if (!event) return { message: "Event not found", data: null, statusCode: 404 };

        await event.update({
            event_type,
            title,
            event_date,
            from_time,
            to_time,
            location,
            description,
            sub_title,
            image
        });
        return { message: "Event updated successfully", data: null, statusCode: 200 };
    } catch (error) {
        return {
            message: error.message.split(":")[0],
            statusCode: 500,
            data: null
        }
    }
}

//book event
export async function bookAnEvent(req) {
    try {
        const { event_id, member_code } = req.body
        const result = await Event_Booking.create({
            event_id, member_code
        })
        return {
            message: "Event booking was successful",
            statusCode: 200,
            data: result
        }
    } catch (error) {
        return {
            message: error.message.split(":")[0],
            statusCode: 500,
            data: null
        }
    }

}
//update event booking
export async function updateAnEvent(req) {
    try {
        const { id, event_id, member_code } = req.body
        const event_booking = await Event_Booking.findByPk(id);
        if (!event_booking) {
            return {
                message: "No Event booking was found",
                statusCode: 404,
                data: event_booking
            }
        }
        const result = await Event_Booking.update({
            event_id, member_code
        })
        return {
            message: "Event booking was updated successful",
            statusCode: 200,
            data: result
        }
    } catch (error) {
        return {
            message: error.message.split(":")[0],
            statusCode: 500,
            data: null
        }
    }

}

//get all  events booking
export async function getAllBookedEvents() {
    try {
        const results = await Event_Booking.findAll()
        return {
            message: "events booking fetched successfully",
            statusCode: 200,
            data: results
        }
    } catch (error) {
        return {
            message: error.message.split(":")[0],
            statusCode: 500,
            data: null
        }
    }
}

//get event booking by id
export async function getEventBookingById(id) {
    try {
        const result = await Event_Booking.findByPk(id)
        return {
            message: "event booking fetched successfully",
            statusCode: 200,
            data: result
        }
    } catch (error) {
        return {
            message: error.message.split(":")[0],
            statusCode: 500,
            data: null
        }
    }

}

//get event booking by event id
export async function getEventBookingByEventId(event_id) {
    try {
        const result = await Event_Booking.findAll({ where: { event_id } })
        return {
            message: "event booking fetched successfully",
            statusCode: 200,
            data: result
        }
    } catch (error) {
        return {
            message: error.message.split(":")[0],
            statusCode: 500,
            data: null
        }
    }
}

//get event booking by member_code
export async function getEventBookingByMemberCode(member_code) {
    try {
        const result = await Event_Booking.findAll({ where: { member_code } })
        return {
            message: "event booking fetched successfully",
            statusCode: 200,
            data: result
        }
    } catch (error) {
        return {
            message: error.message.split(":")[0],
            statusCode: 500,
            data: null
        }
    }
}

// Get events for landing page (latest 3)
export async function getLandingEvents() {
    try {
        const result = await Events.findAll({
            limit: 3,
            order: [['event_date', 'DESC']]
        });
        return {
            message: "Landing events fetched successfully",
            statusCode: 200,
            data: result
        }
    } catch (error) {
        return {
            message: error.message.split(":")[0],
            statusCode: 500,
            data: null
        }
    }
}
