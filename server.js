require("dotenv").config();
const express = require("express");
const admin = require("firebase-admin");
const WebSocket = require("ws");
const cors = require("cors");
const fs = require("fs");

const simulator = true;
// Initialize Firebase Admin SDK
const serviceAccount = require("/etc/secrets/serviceAccountKey.json");
//const serviceAccount = require("./serviceAccountKey.json");

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

function broadcastMessage(message) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

const activeListeners = new Set(); // Track chatrooms with active listeners

db.ref("chatrooms").on("child_added", (snapshot) => {
  const chatroomId = snapshot.key;

  // Attach listener ONLY if it hasn't been attached before
  if (!activeListeners.has(chatroomId)) {
    activeListeners.add(chatroomId);
    console.log(`✅ Listening for messages in chatroom: ${chatroomId}`);

    db.ref(`chatrooms/${chatroomId}/messages`).on(
      "child_added",
      (messageSnapshot) => {
        const lastMsg = messageSnapshot.val();

        console.log(
          `📨 Detected NEW_MESSAGE from ${lastMsg.userId}: "${lastMsg.text}"`
        );

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
          }
        });
      }
    );
  }
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
        return res
          .status(403)
          .json({ error: "You are not a member of this private chatroom." });
      }
    }

    // 4. Store the message in Firebase
    const newMsgRef = db.ref(`chatrooms/${chatroomId}/messages`).push();
    const messageData = {
      text: text.trim(),
      userId: userEmail,
      timestamp: Date.now(),
    };
    await newMsgRef.set(messageData);

    console.log(
      `✅ ${userEmail} sent message to chatroom ${chatroomId}: "${text}"`
    );
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

// GET /chatrooms/:id/users
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
