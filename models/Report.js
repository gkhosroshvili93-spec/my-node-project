const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
    reporter: String, // Email
    type: String, // post, user
    targetId: String,
    reason: String,
    timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Report', reportSchema);
