const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
    userId: { type: String, required: true }, // To whom (Email)
    type: String, // like, comment, friend_request, story_reaction
    from: {
        name: String,
        avatar: String,
        email: String
    },
    relatedId: String, // PostId or StoryId
    message: String,
    read: { type: Boolean, default: false },
    timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Notification', notificationSchema);
