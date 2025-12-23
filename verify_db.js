require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

const MONGO_URI = process.env.MONGO_URI;
console.log("Connecting to:", MONGO_URI.replace(/:([^:@]+)@/, ':****@')); // Hide password

mongoose.connect(MONGO_URI)
.then(async () => {
    console.log('✅ Connected to MongoDB Atlas!');
    
    // Count users
    const count = await User.countDocuments();
    console.log(`📊 Total Users in DB: ${count}`);
    
    // List users
    const users = await User.find({}, 'email firstName lastName');
    console.log("\n📋 User List:");
    users.forEach(u => {
        console.log(`- ${u.firstName} ${u.lastName} (${u.email})`);
    });

    mongoose.connection.close();
})
.catch(err => {
    console.error('❌ Connection Error:', err);
    process.exit(1);
});
