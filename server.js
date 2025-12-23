require("dotenv").config();
// საჭირო ბიბლიოთეკების შემოტანა
const express = require("express");
const mongoose = require("mongoose");

// Models
const User = require("./models/User");
const Post = require("./models/Post");
const Chat = require("./models/Chat");
const Story = require("./models/Story");
const News = require("./models/News");
const Notification = require("./models/Notification");
const Report = require("./models/Report");

// Global Error Handlers (Crash Prevention)
process.on("uncaughtException", (err) => {
  console.error("CRITICAL ERROR (Uncaught Exception):", err);
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("CRITICAL ERROR (Unhandled Rejection):", reason);
});

const session = require("express-session");
const bodyParser = require("body-parser");
const { authenticator } = require("otplib");
const multer = require("multer"); // ფაილების ატვირთვა

const QRCode = require("qrcode");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs"); // პაროლების ჰეშირება
const rateLimit = require("express-rate-limit");
const svgCaptcha = require("svg-captcha");
const crypto = require("crypto"); // For encryption
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const port = process.env.PORT || 3000;

// MongoDB Connection
// Default to local if no env provided, but user will provide Atlas URI in env
const MONGO_URI =
  process.env.MONGO_URI || "mongodb://localhost:27017/socialportal";
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB Connected Successfully"))
  .catch((err) => console.error("MongoDB Connection Error:", err));

// Multer კონფიგურაცია
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = "./public/uploads";
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = filetypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb("შეცდომა: მხოლოდ სურათებია დაშვებული!");
    }
  },
});

const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;

const loginLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100,
  message: "Too many login attempts",
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

// Session
app.use(
  session({
    secret: process.env.SESSION_SECRET || "super-secret-key-georgia",
    resave: false,
    saveUninitialized: true,
  })
);

// Encryption Helpers
const ENCRYPTION_KEY = crypto.scryptSync(
  process.env.ENCRYPTION_KEY || "my-super-secret-password-123",
  "salt",
  32
);
const IV_LENGTH = 16;

function encrypt(text) {
  if (!text) return text;
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

function decrypt(text) {
  if (!text) return text;
  try {
    const textParts = text.split(":");
    if (textParts.length < 2) return text;
    const iv = Buffer.from(textParts.shift(), "hex");
    const encryptedText = Buffer.from(textParts.join(":"), "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch (e) {
    return text;
  }
}

// Global Middleware for Notifications and User
app.use(async (req, res, next) => {
  if (req.session.isAuthenticated) {
    try {
      const myNotifications = await Notification.find({
        userId: req.session.userEmail,
      })
        .sort({ timestamp: -1 })
        .limit(20);
      const unreadCount = myNotifications.filter((n) => !n.read).length;
      res.locals.notifications = myNotifications;
      res.locals.unreadNotificationsCount = unreadCount;

      // Also make currentUser available if needed, though usually passed explicitly
      const user = await User.findOne({ email: req.session.userEmail });
      res.locals.currentUser = user;
    } catch (e) {
      console.error(e);
      res.locals.notifications = [];
      res.locals.unreadNotificationsCount = 0;
    }
  } else {
    res.locals.notifications = [];
    res.locals.unreadNotificationsCount = 0;
  }
  next();
});

// --- Routes ---

app.get("/", (req, res) => {
  if (req.session.isAuthenticated) {
    return res.redirect("/dashboard");
  }
  res.redirect("/login");
});

app.get("/captcha", (req, res) => {
  const captcha = svgCaptcha.create();
  req.session.captcha = captcha.text;
  res.type("svg");
  res.status(200).send(captcha.data);
});

// Auth Routes
app.get("/register", (req, res) => {
  res.render("register", { error: null, formData: {} });
});

app.post("/register", async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      username,
      email,
      password,
      confirmPassword,
      securityQuestion,
      securityAnswer,
    } = req.body;

    if (
      !firstName ||
      !lastName ||
      !username ||
      !email ||
      !password ||
      !confirmPassword ||
      !securityQuestion ||
      !securityAnswer
    ) {
      return res.render("register", {
        error: "გთხოვთ შეავსოთ ყველა ველი",
        formData: req.body,
      });
    }

    if (password !== confirmPassword) {
      return res.render("register", {
        error: "პაროლები არ ემთხვევა",
        formData: req.body,
      });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.render("register", {
        error: "ელ.ფოსტა ან მომხმარებლის სახელი დაკავებულია",
        formData: req.body,
      });
    }

    const hashedAnswer = await bcrypt.hash(
      securityAnswer.toLowerCase().trim(),
      10
    );
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      firstName,
      lastName,
      username,
      email,
      password: hashedPassword,
      securityQuestion,
      securityAnswer: hashedAnswer,
      role: "user",
      friends: [],
      friendRequestsSent: [],
      friendRequestsReceived: [],
    });

    await newUser.save();

    req.session.isAuthenticated = true;
    req.session.userEmail = email;
    res.redirect("/dashboard");
  } catch (e) {
    console.error(e);
    require("fs").appendFileSync(
      "error_log.txt",
      JSON.stringify(e, Object.getOwnPropertyNames(e)) + "\n"
    );

    res.render("register", {
      error: "სისტემური შეცდომა",
      formData: req.body || {},
    });
  }
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password, captcha } = req.body;

    if (!process.env.SKIP_CAPTCHA) {
      // Optional generic flag
      if (!req.session.captcha || req.session.captcha !== captcha) {
        delete req.session.captcha;
        return res.render("login", { error: "Captcha კოდი არასწორია", email });
      }
    }
    delete req.session.captcha;

    const user = await User.findOne({ email });
    if (!user) {
      return res.render("login", {
        error: "ელ.ფოსტა ან პაროლი არასწორია",
        email,
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render("login", {
        error: "ელ.ფოსტა ან პაროლი არასწორია",
        email,
      });
    }

    if (user.is2faSetup) {
      req.session.preLoginEmail = email;
      return res.redirect("/verify-2fa");
    }

    req.session.isAuthenticated = true;
    req.session.userEmail = email;
    res.redirect("/dashboard");
  } catch (e) {
    console.error(e);
    res.render("login", { error: "სისტემური შეცდომა", email });
  }
});

// 2FA
app.get("/verify-2fa", (req, res) => {
  if (!req.session.preLoginEmail) return res.redirect("/login");
  res.render("verify-2fa", { error: null });
});

app.post("/verify-2fa", async (req, res) => {
  const { token } = req.body;
  const email = req.session.preLoginEmail;
  const user = await User.findOne({ email });

  const isValid = authenticator.check(token, user.twofaSecret);

  if (isValid) {
    req.session.isAuthenticated = true;
    req.session.userEmail = email;
    delete req.session.preLoginEmail;
    res.redirect("/dashboard");
  } else {
    res.render("verify-2fa", { error: "არასწორი კოდი" });
  }
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

// Dashboard
app.get("/dashboard", async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  try {
    const currentUser = await User.findOne({ email: req.session.userEmail });

    // Fetch all needed data
    const allPosts = await Post.find({}).sort({ timestamp: -1 });
    const groupedStories = {};
    const allStories = await Story.find({});

    // Get authors for stories to mimic grouping
    // Grouping logic: Key is author email or ID. EJS iterates keys.
    // We'll group by userId (email)
    for (const s of allStories) {
      if (!groupedStories[s.userId]) groupedStories[s.userId] = [];
      groupedStories[s.userId].push(s);
    }

    // News Feed Logic
    let newsFeed = [];
    // Allow ONLY friends (accepted) and own posts + Public posts logic
    // Current logic was: all posts except FriendsOnly ones from non-friends.

    // We need 'users' object for EJS (contacts sidebar)
    // Ideally we only fetch friends, but code uses 'users' global object.
    // Let's fetch all users for now (Not scalable for millions, but fine for small app)
    const allUsersList = await User.find({});
    const usersMap = {}; // Map for O(1) access
    allUsersList.forEach((u) => (usersMap[u.email] = u));

    newsFeed = allPosts.filter((p) => {
      const isMyPost = p.userId === currentUser.email;
      const isFriend = currentUser.friends.includes(p.userId);
      const isPublic = !p.privacy || p.privacy === "public";

      // Show: Own posts OR Public Posts OR Friends posts (regardless of privacy? No, friend post with friend privacy is visible. Friend post with public is visible.)
      // If post is 'friends', viewer must be friend (or owner).
      if (p.privacy === "friends") {
        return isMyPost || isFriend;
      }
      // If public, visible to all
      return true;
    });

    // Mock friendsData for EJS
    const friendsData = {
      [currentUser.email]: {
        friends: currentUser.friends || [],
        requests_sent: currentUser.friendRequestsSent || [],
        requests_received: currentUser.friendRequestsReceived || [],
      },
    };

    const userFriends = (currentUser.friends || [])
      .map((email) => usersMap[email])
      .filter((u) => u); // full user objects

    res.render("dashboard", {
      user: currentUser,
      users: usersMap, // Passing full map might be heavy but EJS uses it for sidebar contacts (filtering there)
      news: newsFeed,
      groupedStories,
      friendRequestsCount: (currentUser.friendRequestsReceived || []).length,
      userFriends,
      friendsData,
      stories: groupedStories,
      contacts: allUsersList
    });
  } catch (e) {
    console.error(e);
    res.status(500).send("Server Error");
  }
});

// Create Post
app.post("/posts/create", upload.single("image"), async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  try {
    const currentUser = await User.findOne({ email: req.session.userEmail });
    const { content, feeling, privacy } = req.body;

    const newPost = new Post({
      userId: currentUser.email,
      authorName: currentUser.firstName + " " + currentUser.lastName,
      authorAvatar: currentUser.avatar,
      content,
      image: req.file ? "/uploads/" + req.file.filename : "",
      feeling: feeling,
      feelingIcon: feeling ? "😊" : "", // Simplified icon logic
      privacy: privacy || "public",
      likes: [],
      comments: [],
    });

    await newPost.save();
    res.redirect("/dashboard");
  } catch (e) {
    console.error(e);
    res.redirect("/dashboard");
  }
});

// Like Post
app.post("/post/like/:id", async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  try {
    const post =
      (await Post.findOne({ _id: req.params.id })) ||
      (await Post.findOne({ id: req.params.id })); // Try both ID types
    if (post) {
      const myEmail = req.session.userEmail;
      const index = post.likes.indexOf(myEmail);

      if (index === -1) {
        post.likes.push(myEmail);
        if (post.userId !== myEmail) {
          const me = await User.findOne({ email: myEmail });
          // Create Notification
          const notif = new Notification({
            userId: post.userId,
            type: "like",
            from: {
              name: me.firstName + " " + me.lastName,
              avatar: me.avatar,
              email: me.email,
            },
            relatedId: post.id || post._id,
            message: "რა მაგარია! დაალაიქა თქვენი პოსტი.",
          });
          await notif.save();
        }
      } else {
        post.likes.splice(index, 1);
      }
      await post.save();
    }
  } catch (e) {
    console.error(e);
  }
  res.redirect("back");
});

// Comment Post
app.post("/post/comment/:id", async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  try {
    const { comment } = req.body;
    const post =
      (await Post.findOne({ _id: req.params.id })) ||
      (await Post.findOne({ id: req.params.id }));
    if (post && comment) {
      const me = await User.findOne({ email: req.session.userEmail });
      post.comments.push({
        authorName: me.firstName + " " + me.lastName,
        authorEmail: me.email,
        authorAvatar: me.avatar,
        text: comment,
      });
      await post.save();

      if (post.userId !== me.email) {
        const notif = new Notification({
          userId: post.userId,
          type: "comment",
          from: {
            name: me.firstName + " " + me.lastName,
            avatar: me.avatar,
            email: me.email,
          },
          relatedId: post.id || post._id,
          message: "დააკომენტარა თქვენს პოსტზე",
        });
        await notif.save();
      }
    }
  } catch (e) {
    console.error(e);
  }
  res.redirect("back");
});

// Delete Post
app.post("/post/delete/:id", async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  try {
    await Post.deleteOne({ _id: req.params.id, userId: req.session.userEmail });
    // Also support legacy ID deletion if using numbers
    // await Post.deleteOne({ id: req.params.id, userId: req.session.userEmail });
  } catch (e) {
    console.error(e);
  }
  res.redirect("/dashboard");
});

// Stories
app.post("/story/create", upload.single("image"), async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  try {
    const currentUser = await User.findOne({ email: req.session.userEmail });
    const { type, text, background } = req.body;

    const newStory = new Story({
      userId: currentUser.email,
      authorName: currentUser.firstName + " " + currentUser.lastName,
      authorAvatar: currentUser.avatar,
      image:
        type === "photo" && req.file ? "/uploads/" + req.file.filename : "",
      text: type === "text" ? text : "",
      background: type === "text" ? background : "",
    });
    await newStory.save();
  } catch (e) {
    console.error(e);
  }
  res.redirect("/dashboard");
});

app.post("/story/delete/:id", async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  try {
    await Story.deleteOne({
      _id: req.params.id,
      userId: req.session.userEmail,
    });
  } catch (e) {
    console.error(e);
  }
  res.redirect("/dashboard");
});

// Chat Page
app.get("/chat", async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  try {
    // Same mock logic for users data
    const allUsers = await User.find({});
    const usersMap = {};
    allUsers.forEach((u) => (usersMap[u.email] = u));

    const currentUser = usersMap[req.session.userEmail];
    const friendRequestsCount = (currentUser.friendRequestsReceived || [])
      .length;

    res.render("chat", {
      user: currentUser,
      users: usersMap,
      friendRequestsCount,
    });
  } catch (e) {
    console.error(e);
    res.redirect("/dashboard");
  }
});

// Chat API History
app.get("/api/chat/history/:withEmail", async (req, res) => {
  if (!req.session.isAuthenticated)
    return res.status(401).json({ error: "Unauthorized" });
  try {
    const myEmail = req.session.userEmail;
    const withEmail = req.params.withEmail;

    const history = await Chat.find({
      $or: [
        { sender: myEmail, receiver: withEmail },
        { sender: withEmail, receiver: myEmail },
      ],
    }).sort({ timestamp: 1 });

    // Decrypt messages before sending
    const decryptedHistory = history.map((msg) => ({
      ...msg.toObject(),
      message: decrypt(msg.message),
    }));

    res.json(decryptedHistory);
  } catch (e) {
    res.json([]);
  }
});

// Socket.io for Chat
io.on("connection", (socket) => {
  socket.on("join-room", (email) => {
    socket.join(email);
  });

  socket.on("send-message", async (data) => {
    const { sender, receiver, message, type } = data; // type for 'global'

    // Save to DB
    const savedMsg = new Chat({
      sender,
      receiver: receiver || "global",
      message: encrypt(message),
      // Cached fields for simplicity
      username: data.username,
      avatar: data.avatar,
    });
    await savedMsg.save();

    // Emit decrypted
    const payload = { ...data, timestamp: savedMsg.timestamp };

    if (receiver && receiver !== "global") {
      io.to(receiver).emit("receive-message", payload);
      io.to(sender).emit("receive-message", payload); // Echo back
    } else {
      io.emit("receive-message", payload); // Global
    }
  });

  // ... WebRTC ...
  socket.on("call-user", (data) => {
    io.to(data.userToCall).emit("call-made", {
      offer: data.offer,
      socket: socket.id,
      fromUser: data.fromUser,
    });
  });
  socket.on("make-answer", (data) => {
    io.to(data.to).emit("answer-made", {
      socket: socket.id,
      answer: data.answer,
    });
  });
  socket.on("ice-candidate", (data) => {
    io.to(data.to).emit("ice-candidate", { candidate: data.candidate });
  });
  socket.on("end-call", (data) => {
    io.to(data.to).emit("call-ended", { from: socket.id });
  });
});

// Profiles List
app.get("/profiles", async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  const currentUser = await User.findOne({ email: req.session.userEmail });
  const users = await User.find({ email: { $ne: "admin" } });
  res.render("profiles", { currentUser, users });
});

// User Profile
app.get("/user/:email", async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  try {
    const targetEmail = req.params.email;
    const targetUser = await User.findOne({ email: targetEmail });
    const currentUser = await User.findOne({ email: req.session.userEmail });

    if (!targetUser) return res.redirect("/dashboard");

    const allPosts = await Post.find({ userId: targetEmail }).sort({
      timestamp: -1,
    });
    // Privacy filter
    const isSelf = currentUser.email === targetEmail;
    const isFriend = (currentUser.friends || []).includes(targetEmail);

    const userPosts = allPosts.filter((p) => {
      const isPublic = !p.privacy || p.privacy === "public";
      return isSelf || isFriend || isPublic;
    });

    const friendRequestsCount = (currentUser.friendRequestsReceived || [])
      .length;

    res.render("user-profile", {
      currentUser,
      targetUser,
      userPosts,
      isFriend,
      isRequestSent: (currentUser.friendRequestsSent || []).includes(
        targetEmail
      ),
      isRequestReceived: (currentUser.friendRequestsReceived || []).includes(
        targetEmail
      ),
      isBlocked: (currentUser.blocked || []).includes(targetEmail),
      friendRequestsCount,
    });
  } catch (e) {
    console.error(e);
    res.redirect("/dashboard");
  }
});

// Friend Actions
app.get("/friends/add/:email", async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  const targetEmail = req.params.email;
  const myEmail = req.session.userEmail;

  // Add to my sent, add to target received
  await User.updateOne(
    { email: myEmail },
    { $addToSet: { friendRequestsSent: targetEmail } }
  );
  await User.updateOne(
    { email: targetEmail },
    { $addToSet: { friendRequestsReceived: myEmail } }
  );

  // Notify
  const me = await User.findOne({ email: myEmail });
  const notif = new Notification({
    userId: targetEmail,
    type: "friend_request",
    from: {
      name: me.firstName + " " + me.lastName,
      avatar: me.avatar,
      email: me.email,
    },
    message: "მეგობრობის თხოვნა გამოგიგზავნათ",
  });
  await notif.save();

  res.redirect("back");
});

app.get("/friends/accept/:email", async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  const targetEmail = req.params.email;
  const myEmail = req.session.userEmail;

  // Add to friends, remove from requests
  await User.updateOne(
    { email: myEmail },
    {
      $addToSet: { friends: targetEmail },
      $pull: { friendRequestsReceived: targetEmail },
    }
  );
  await User.updateOne(
    { email: targetEmail },
    {
      $addToSet: { friends: myEmail },
      $pull: { friendRequestsSent: myEmail },
    }
  );

  res.redirect("back");
});

// Friends Page
// Friends Page
app.get("/friends", async (req, res) => {
    if (!req.session.isAuthenticated) return res.redirect("/login");
    try {
        const currentUser = await User.findOne({ email: req.session.userEmail });
        const allUsers = await User.find({});
        const usersMap = {};
        allUsers.forEach(u => usersMap[u.email] = u);
        
        // Prepare lists for EJS
        const friendsList = (currentUser.friends || []).map(email => usersMap[email]).filter(u => u);
        const receivedList = (currentUser.friendRequestsReceived || []).map(email => usersMap[email]).filter(u => u);
        
        // Suggestions: users who are not me, not my friends, and not in my sent/received requests
        const suggestionsList = allUsers.filter(u => {
            if (u.email === currentUser.email) return false;
            // Check if already friend
            if (currentUser.friends.includes(u.email)) return false;
            // Check if request sent
            if ((currentUser.friendRequestsSent || []).includes(u.email)) return false;
            // Check if request received
            if ((currentUser.friendRequestsReceived || []).includes(u.email)) return false;
            return true;
        });

        res.render("friends", {
            user: currentUser,
            friends: friendsList,
            received: receivedList,
            suggestions: suggestionsList,
            friendRequestsCount: receivedList.length
        });
    } catch(e) { console.error(e); res.redirect("/dashboard"); }
});

// News
app.get("/news", async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  const currentUser = await User.findOne({ email: req.session.userEmail });
  const news = await News.find({}); // reverse if needed

  res.render("news", {
    currentUser,
    news: news.reverse(),
    friendRequestsCount: (currentUser.friendRequestsReceived || []).length,
  });
});

app.post("/news/add", async (req, res) => {
  if (!req.session.isAuthenticated) return res.redirect("/login");
  // Admin check removed as per previous request
  const { title, content } = req.body;
  const currentUser = await User.findOne({ email: req.session.userEmail });

  const n = new News({
    title,
    content,
    author: currentUser.firstName + " " + currentUser.lastName,
    date: new Date().toLocaleDateString("ka-GE"),
  });
  await n.save();
  res.redirect("/news");
});

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
