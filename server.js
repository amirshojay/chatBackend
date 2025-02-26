require("dotenv").config();
const express = require("express");
const admin = require("firebase-admin");
const WebSocket = require("ws");
const cors = require("cors");
const fs = require("fs");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const upload = multer({ storage: multer.memoryStorage() });

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Initialize Firebase Admin SDK
//const serviceAccount = require("/etc/secrets/serviceAccountKey.json");
const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://dodgechatofficial-default-rtdb.firebaseio.com",
});

const db = admin.database();
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
  console.log(`📩 Incoming request: ${req.method} ${req.url}`);
  next();
});

// WebSocket Server
const wss = new WebSocket.Server({ noServer: true });

//🔹 Middleware to Verify Firebase `idToken` in API Requests
async function verifyToken(req, res, next) {
  const token =
    req.query.auth || req.headers.authorization?.split("Bearer ")[1];
  if (!token) {
    console.log("❌ No token provided!");
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    console.log("🔹 Verifying token:", token.substring(0, 20) + "..."); // Print part of token for debugging
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    console.log("✅ Token verified for:", decodedToken.email);
    next();
  } catch (error) {
    console.log("❌ Token verification failed:", error.message);
    return res.status(403).json({ error: "Invalid or expired token" });
  }
}

//GET METHOD
// Get all chatrooms
app.get("/chatrooms", async (req, res) => {
  try {
    const snapshot = await db.ref("chatrooms").once("value");
    if (!snapshot.exists())
      return res.json({ message: "No chatrooms available" });

    const chatrooms = snapshot.val();
    res.json(chatrooms);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// 🔹 API Endpoint: Fetch Chat Messages
app.get("/chatrooms/:id/messages", async (req, res) => {
  const chatroomId = req.params.id;
  try {
    const snapshot = await db
      .ref(`chatrooms/${chatroomId}/messages`)
      .once("value");
    res.json(snapshot.exists() ? snapshot.val() : []);
  } catch (error) {
    console.error("❌ Error fetching messages:", error.message);
    res.status(500).json({ error: error.message });
  }
});
// Get chatroom users
app.get("/chatrooms/:id/users", verifyToken, async (req, res) => {
  try {
    const chatroomId = req.params.id;
    const snapshot = await db.ref(`chatrooms/${chatroomId}`).once("value");
    if (!snapshot.exists()) {
      return res.status(404).json({ error: "Chatroom not found" });
    }

    const chatroomData = snapshot.val();
    const membersObj = chatroomData.members || {};
    // membersObj might look like:
    // { "user_example_com": true, "another_user_com": true }

    // Convert keys "user_example_com" -> "user@example.com"
    const membersList = Object.keys(membersObj).map((key) =>
      key.replace(/_/g, ".")
    );
    // e.g. ["user@example.com", "another@user.com"]

    res.json(membersList);
  } catch (error) {
    console.error("Error fetching chatroom users:", error);
    res.status(500).json({ error: error.message });
  }
});

//POST METHOD
// Create a new chatroom
app.post("/chatrooms", verifyToken, async (req, res) => {
  const { name, isPrivate, password, createdBy, maxUsers } = req.body;

  if (!name)
    return res.status(400).json({ error: "Chatroom name is required" });

  const chatroomData = {
    name,
    isPrivate,
    password: isPrivate ? password : null,
    createdBy,
    maxUsers: maxUsers || 16, // or some default
    createdAt: new Date().toISOString(),
  };

  try {
    console.log("📌 Creating chatroom:", chatroomData);
    const newChatroomRef = db.ref("chatrooms").push();
    await newChatroomRef.set(chatroomData);
    console.log("✅ Chatroom created:", newChatroomRef.key);
    res.json({
      message: "Chatroom created successfully!",
      chatroomId: newChatroomRef.key,
    });
  } catch (error) {
    console.log("❌ Firebase error:", error.message);
    res.status(500).json({ error: error.message });
  }
});
// Logout route
app.post("/logout", async (req, res) => {
  try {
    const idToken = req.body.idToken; // 🔹 Get the token from the client
    if (!idToken) {
      return res.status(400).json({ error: "Missing token" });
    }

    // 🔹 Verify and revoke the session token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    await admin.auth().revokeRefreshTokens(decodedToken.uid);

    console.log(`🚪 User ${decodedToken.email} logged out.`);
    return res.json({ message: "User logged out successfully" });
  } catch (error) {
    console.error("❌ Error logging out:", error);
    return res.status(500).json({ error: "Failed to log out" });
  }
});
// Join a chatroom
app.post("/chatrooms/:id/join", verifyToken, async (req, res) => {
  try {
    const chatroomId = req.params.id;
    const { password } = req.body;
    const userEmail = req.user.email;
    const userKey = userEmail.replace(/\./g, "_");

    console.log(
      `📩 Incoming request: JOIN chatroom ${chatroomId} for user ${userEmail} (Key: ${userKey})`
    );

    // 1️⃣ Fetch the chatroom data
    const snapshot = await db.ref(`chatrooms/${chatroomId}`).once("value");
    if (!snapshot.exists()) {
      console.log(`❌ Chatroom ${chatroomId} not found.`);
      return res.status(404).json({ error: "Chatroom not found" });
    }

    const chatroomData = snapshot.val();
    console.log(`🔍 Chatroom Data:`, chatroomData);

    // 2️⃣ Check if the user is already a member
    if (chatroomData.members && chatroomData.members[userKey]) {
      console.log(`⚠ User ${userEmail} is already a member.`);
      return res.status(409).json({ error: "User is already a member" });
    }

    // 3️⃣ Check chatroom user limit (Fix: Use correct field `maxUsers`)
    const currentMembers = chatroomData.members
      ? Object.keys(chatroomData.members).length
      : 0;
    const maxUsers = chatroomData.maxUsers || Infinity; // ✅ Fix: Correct field name

    console.log(
      `👥 Current Members: ${currentMembers}, Max Allowed: ${maxUsers}`
    );

    if (currentMembers >= maxUsers) {
      console.log(
        `🚫 Chatroom ${chatroomId} is full. Cannot add ${userEmail}.`
      );
      return res.status(403).json({ error: "Chatroom is full" });
    }

    // 4️⃣ Check if private + password
    if (chatroomData.isPrivate) {
      if (!password) {
        console.log(`❌ Password required but not provided.`);
        return res
          .status(400)
          .json({ error: "Password is required for private chatrooms" });
      }
      if (chatroomData.password !== password) {
        console.log(`❌ Incorrect password entered.`);
        return res.status(403).json({ error: "Incorrect password" });
      }
    }

    // 5️⃣ Add user to chatroom
    const updates = {};
    updates[`chatrooms/${chatroomId}/members/${userKey}`] = true;
    await db.ref().update(updates);

    console.log(`✅ ${userEmail} successfully joined chatroom: ${chatroomId}`);
    return res.json({
      message: `You joined chatroom: ${chatroomData.name}`,
      chatroomId,
    });
  } catch (error) {
    console.error("❌ Error joining chatroom:", error);
    return res.status(500).json({ error: error.message });
  }
});
// Leave a chatroom
app.post("/chatrooms/:chatroomId/leave", async (req, res) => {
  const chatroomId = req.params.chatroomId;
  const token = req.query.auth;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized: Missing auth token" });
  }

  try {
    // 🔹 Verify Firebase token
    const decodedToken = await admin.auth().verifyIdToken(token);
    let userId = decodedToken.email;

    // 🔹 Convert email to Firebase-safe format
    const firebaseSafeUserId = userId.replace(/\./g, "_");

    console.log(
      `📩 Incoming request: Leave chatroom ${chatroomId} for user ${userId} (Firebase Key: ${firebaseSafeUserId})`
    );

    // 🔹 Log existing members before removal
    const membersSnapshot = await db
      .ref(`chatrooms/${chatroomId}/members`)
      .once("value");
    console.log(`👥 Members in chatroom ${chatroomId}:`, membersSnapshot.val());

    const chatroomRef = db.ref(
      `chatrooms/${chatroomId}/members/${firebaseSafeUserId}`
    );

    // 🔹 Check if user exists in the chatroom
    const snapshot = await chatroomRef.once("value");
    if (!snapshot.exists()) {
      console.log(
        `❌ User ${firebaseSafeUserId} not found in chatroom ${chatroomId}`
      );
      return res.status(404).json({ error: "User not in chatroom" });
    }

    // 🔹 Remove user from chatroom
    await chatroomRef.remove();

    // 🔹 Check if chatroom is empty, and delete if needed
    const updatedMembers = await db
      .ref(`chatrooms/${chatroomId}/members`)
      .once("value");
    if (!updatedMembers.exists()) {
      await db.ref(`chatrooms/${chatroomId}`).remove();
    }

    // 🔹 Broadcast WebSocket event (ensure function exists)
    if (typeof broadcastMessage === "function") {
      const leavePayload = {
        type: "USER_LEFT",
        chatroomId: chatroomId,
        user: userId,
      };
      broadcastMessage(leavePayload);
    } else {
      console.error("❌ Error: broadcastMessage is not defined");
    }

    console.log(`🚪 User ${userId} left chatroom ${chatroomId}`);
    res.json({ success: true, message: "Left chatroom successfully" });
  } catch (error) {
    console.error("❌ Error leaving chatroom:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/chatrooms/:id/messages", upload.single("file"), async (req, res) => {
  const chatroomId = req.params.id;
  let { text, userEmail } = req.body;
  let fileUrl = null;

  try {
    if (!userEmail) {
      return res.status(400).json({ error: "Missing userEmail field" });
    }

    if (req.file) {
      // Upload file to Cloudinary
      const result = await new Promise((resolve, reject) => {
        cloudinary.uploader
          .upload_stream({ folder: "chat_images" }, (error, result) => {
            if (error) reject(error);
            else resolve(result);
          })
          .end(req.file.buffer);
      });
      fileUrl = result.secure_url;
      console.log("✅ Image uploaded to Cloudinary:", fileUrl);
    }

    // Store message in Firebase
    const newMsgRef = db.ref(`chatrooms/${chatroomId}/messages`).push();
    await newMsgRef.set({
      text: text || null, // Ensure text is stored correctly
      fileUrl: fileUrl || null,
      userId: userEmail, // Ensure userId is never undefined
      timestamp: Date.now(),
    });

    res.json({ message: "Message sent!", msgId: newMsgRef.key, fileUrl });
  } catch (error) {
    console.error("❌ Message Send Failed:", error.message);
    res.status(500).json({ error: error.message });
  }
});

function broadcastMessage(message) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

const activeListeners = new Set(); // ✅ Track active chatroom listeners

db.ref("chatrooms").on("child_added", (snapshot) => {
  const chatroomId = snapshot.key;

  if (activeListeners.has(chatroomId)) return; // ✅ Prevent duplicate listeners
  activeListeners.add(chatroomId);

  console.log(`✅ Listening for messages in chatroom: ${chatroomId}`);

  db.ref(`chatrooms/${chatroomId}/messages`).on(
    "child_added",
    (messageSnapshot) => {
      console.log(`🔥 Firebase child_added triggered for messageId`);
      const lastMsg = messageSnapshot.val();
      const messagePayload = {
        type: "NEW_MESSAGE",
        chatroomId,
        user: lastMsg.userId,
        text: lastMsg.text,
        timestamp: lastMsg.timestamp,
      };

      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify(messagePayload));
          console.log(
            `📩 [Broadcasting] Message from ${lastMsg.userId}: "${lastMsg.text}"`
          );
        }
      });
    }
  );
});

const activeMemberListeners = new Set(); // Track chatrooms with active member listeners

db.ref("chatrooms").on("child_added", (snapshot) => {
  const chatroomId = snapshot.key;

  // Attach listener ONLY if it hasn't been attached before
  if (!activeMemberListeners.has(chatroomId)) {
    activeMemberListeners.add(chatroomId);
    console.log(`✅ Listening for member changes in chatroom: ${chatroomId}`);

    // Listen for new members joining
    db.ref(`chatrooms/${chatroomId}/members`).on(
      "child_added",
      (memberSnapshot) => {
        const userId = memberSnapshot.key;
        console.log(`👤 User ${userId} joined chatroom ${chatroomId}`);

        wss.clients.forEach((client) => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(
              JSON.stringify({
                type: "USER_JOINED",
                chatroomId,
                user: userId,
              })
            );
          }
        });
      }
    );

    // Listen for members leaving
    db.ref(`chatrooms/${chatroomId}/members`).on(
      "child_removed",
      (memberSnapshot) => {
        const userId = memberSnapshot.key;
        console.log(`🚪 User ${userId} left chatroom ${chatroomId}`);

        wss.clients.forEach((client) => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(
              JSON.stringify({
                type: "USER_LEFT",
                chatroomId,
                user: userId,
              })
            );
          }
        });
      }
    );
  }
});

db.ref("chatrooms").on("child_removed", (snapshot) => {
  const chatroomId = snapshot.key;
  console.log(`🚨 Chatroom ${chatroomId} was deleted or all users left!`);
});

/**
 * 🔹 WebSocket: Handle Real-Time Messages
 */
wss.on("connection", async (ws, req) => {
  console.log(`🔌 WebSocket connected. Total clients: ${wss.clients.size}`);

  ws.on("message", async (message) => {
    const data = JSON.parse(message);
    const { userId, chatroomId, messageText, idToken } = data;

    const decodedToken = await admin.auth().verifyIdToken(idToken);
    if (!decodedToken)
      return ws.send(JSON.stringify({ error: "Invalid token" }));

    const timestamp = Date.now();
    const newMessage = { userId, messageText, timestamp };

    // ✅ Only save in Firebase, let Firebase's listener handle broadcasting
    await db.ref(`chatrooms/${chatroomId}/messages`).push(newMessage);
  });

  ws.on("close", () => {
    console.log("WebSocket connection closed");
  });
});

/**
 * 🔹 Upgrade HTTP Server to Support WebSockets
 */
const server = app.listen(PORT, () =>
  console.log(`✅ Server running on http://localhost:${PORT}`)
);

server.on("upgrade", (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit("connection", ws, request);
  });
});
