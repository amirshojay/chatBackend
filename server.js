require("dotenv").config();
const express = require("express");
const admin = require("firebase-admin");
const WebSocket = require("ws");
const cors = require("cors");
const fs = require("fs");

// Initialize Firebase Admin SDK
const serviceAccount = require(process.env.FIREBASE_ADMIN_SDK_PATH);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://dodgechatofficial-default-rtdb.firebaseio.com", // 🔹 Replace with your Firebase Realtime DB URL
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

/**
 * 🔹 Middleware to Verify Firebase `idToken` in API Requests
 */
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

// 🔹 Listen for new messages in *all* chatrooms
db.ref("chatrooms").on("child_changed", (snapshot) => {
  const chatroomId = snapshot.key;
  const updatedChatroom = snapshot.val();

  // If `messages` changed, broadcast the latest message
  if (updatedChatroom.messages) {
    // Optionally figure out which message was added
    // For simplicity, just broadcast the entire chatroom's messages
    const payload = {
      type: "CHATROOM_UPDATED",
      chatroomId,
      messages: updatedChatroom.messages
    };

    // Broadcast to all WebSocket clients
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(payload));
      }
    });
  }
});


/**
 * 🔹 GET: Fetch Available Chatrooms
 */
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

/**
 * 🔹 POST: Create a New Chatroom (Requires Authentication)
 */
app.post("/chatrooms", verifyToken, async (req, res) => {
  const { name, isPrivate, password } = req.body;
  const createdBy = req.user.email; // Extract email from verified user token

  if (!name)
    return res.status(400).json({ error: "Chatroom name is required" });

  const chatroomData = {
    name,
    isPrivate: !!isPrivate,
    password: isPrivate ? password : null,
    createdBy,
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

app.post("/chatrooms/:id/join", verifyToken, async (req, res) => {
  try {
    const chatroomId = req.params.id;
    const { password } = req.body; // Password if chatroom is private
    const userEmail = req.user.email; // From verifyToken middleware

    // 1. Fetch the chatroom from Firebase
    const snapshot = await db.ref(`chatrooms/${chatroomId}`).once("value");
    if (!snapshot.exists()) {
      return res.status(404).json({ error: "Chatroom not found" });
    }

    const chatroomData = snapshot.val();
    // 2. Check if private and validate password if needed
    if (chatroomData.isPrivate) {
      if (!password) {
        return res
          .status(400)
          .json({ error: "Password is required for private chatrooms" });
      }
      if (chatroomData.password !== password) {
        return res.status(403).json({ error: "Incorrect password" });
      }
    }

    // 3. Add user to the chatroom's "members"
    // Create "members" node if it doesn't exist
    const updates = {};
    updates[
      `chatrooms/${chatroomId}/members/${userEmail.replace(/\./g, "_")}`
    ] = true;

    await db.ref().update(updates);

    console.log(`✅ ${userEmail} joined chatroom: ${chatroomId}`);
    return res.json({
      message: `You joined chatroom: ${chatroomData.name}`,
      chatroomId,
    });
  } catch (error) {
    console.error("❌ Error joining chatroom:", error);
    return res.status(500).json({ error: error.message });
  }
});

/**
 * POST /chatrooms/:id/messages
 * Body: { text: string }
 * Query/Headers: ?auth=<idToken> or Authorization: Bearer <idToken>
 */
app.post("/chatrooms/:id/messages", verifyToken, async (req, res) => {
  try {
    const chatroomId = req.params.id;
    const userEmail = req.user.email; // from verifyToken
    const { text } = req.body;

    // 1. Validate input
    if (!text || text.trim() === "") {
      return res.status(400).json({ error: "Message text cannot be empty." });
    }

    // 2. Check if chatroom exists
    const snapshot = await db.ref(`chatrooms/${chatroomId}`).once("value");
    if (!snapshot.exists()) {
      return res.status(404).json({ error: "Chatroom not found" });
    }

    // (Optional) 3. Verify the user is a member if the chatroom is private
    const chatroomData = snapshot.val();
    if (chatroomData.isPrivate) {
      const userKey = userEmail.replace(/\./g, "_");
      if (!chatroomData.members || !chatroomData.members[userKey]) {
        return res.status(403).json({ error: "You are not a member of this private chatroom." });
      }
    }

    // 4. Store the message in Firebase
    const newMsgRef = db.ref(`chatrooms/${chatroomId}/messages`).push();
    const messageData = {
      text: text.trim(),
      userId: userEmail,
      timestamp: Date.now()
    };
    await newMsgRef.set(messageData);

    console.log(`✅ ${userEmail} sent message to chatroom ${chatroomId}: "${text}"`);
    res.json({ message: "Message sent successfully", msgId: newMsgRef.key });
  } catch (error) {
    console.error("❌ Error sending message:", error);
    res.status(500).json({ error: error.message });
  }
});


/**
 * GET /chatrooms/:id/messages
 * Query/Headers: ?auth=<idToken> or Authorization: Bearer <idToken>
 * Returns the message list for a given chatroom
 */
app.get("/chatrooms/:id/messages", verifyToken, async (req, res) => {
  try {
    const chatroomId = req.params.id;
    const userEmail = req.user.email; // from verifyToken

    // 1. Fetch chatroom data from Firebase
    const snapshot = await db.ref(`chatrooms/${chatroomId}`).once("value");
    if (!snapshot.exists()) {
      return res.status(404).json({ error: "Chatroom not found" });
    }

    const chatroomData = snapshot.val();

    // (Optional) 2. Check membership if chatroom is private
    //    If you store members in chatroomData.members, verify userEmail in that set.
    // if (chatroomData.isPrivate && (!chatroomData.members || !chatroomData.members[userEmail.replace(/\./g, "_")])) {
    //   return res.status(403).json({ error: "You are not a member of this chatroom" });
    // }

    // 3. Retrieve messages from chatroomData.messages or an empty object
    const messages = chatroomData.messages || {};

    // Return them as JSON
    res.json(messages);
  } catch (error) {
    console.error("❌ Error fetching messages:", error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * 🔹 WebSocket: Handle Real-Time Messages
 */
wss.on("connection", async (ws, req) => {
  console.log("New WebSocket connection established");

  ws.on("message", async (message) => {
    try {
      const data = JSON.parse(message);
      const { userId, chatroomId, messageText, idToken } = data;

      // 🔹 Verify token before allowing messages
      const decodedToken = await admin.auth().verifyIdToken(idToken);
      if (!decodedToken)
        return ws.send(JSON.stringify({ error: "Invalid token" }));

      const timestamp = Date.now();
      const newMessage = { userId, messageText, timestamp };

      // 🔹 Save message in Firebase
      await db.ref(`messages/${chatroomId}`).push(newMessage);

      // 🔹 Broadcast message to all connected clients
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({ chatroomId, ...newMessage }));
        }
      });
    } catch (error) {
      console.error("Error processing message:", error);
    }
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
