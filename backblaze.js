const B2 = require("backblaze-b2");

const b2 = new B2({
  applicationKeyId: process.env.B2_KEY_ID, // Backblaze Key ID
  applicationKey: process.env.B2_APP_KEY, // Backblaze App Key
});

async function authorizeB2() {
  try {
    await b2.authorize();
    console.log("✅ Backblaze B2 Authorized");
  } catch (error) {
    console.error("❌ B2 Authorization Failed:", error.message);
  }
}

module.exports = { b2, authorizeB2 };
