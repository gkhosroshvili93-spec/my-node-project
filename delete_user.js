require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');
const Post = require('./models/Post');
const Chat = require('./models/Chat');
const Story = require('./models/Story');

const MONGO_URI = process.env.MONGO_URI;
const emailToDelete = process.argv[2]; // Get email from command line argument

if (!emailToDelete) {
    console.error("❌ Please provide an email address.");
    console.log("Usage: node delete_user.js user@example.com");
    process.exit(1);
}

mongoose.connect(MONGO_URI)
.then(async () => {
    console.log(`🔍 Searching for user: ${emailToDelete}...`);
    
    const user = await User.findOne({ email: emailToDelete });
    
    if (!user) {
        console.log("❌ User not found!");
        process.exit(1);
    }

    console.log(`✅ Found user: ${user.firstName} ${user.lastName}`);
    
    // Delete related data (Optional but recommended)
    await Post.deleteMany({ userId: emailToDelete });
    console.log("🗑️  Deleted user posts");
    
    await Story.deleteMany({ userId: emailToDelete });
    console.log("🗑️  Deleted user stories");
    
    // Chats are tricky (sender OR receiver), maybe leave them or delete
    // await Chat.deleteMany({ $or: [{ sender: emailToDelete }, { receiver: emailToDelete }] });
    
    // Delete User
    await User.deleteOne({ email: emailToDelete });
    console.log(`✅ User ${emailToDelete} successfully deleted!`);

    mongoose.connection.close();
})
.catch(err => {
    console.error('❌ Error:', err);
    process.exit(1);
});
