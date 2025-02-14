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
