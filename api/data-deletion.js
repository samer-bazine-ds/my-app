import crypto from "node:crypto";

function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(normalized, "base64");
}

function parseSignedRequest(signedRequest, secret) {
  const [encodedSignature, encodedPayload] = String(signedRequest || "").split(".", 2);
  if (!encodedSignature || !encodedPayload) {
    throw new Error("Missing or malformed signed_request");
  }

  const payload = JSON.parse(decodeBase64Url(encodedPayload).toString("utf8"));
  if (String(payload.algorithm || "").toUpperCase() !== "HMAC-SHA256") {
    throw new Error("Unsupported signature algorithm");
  }

  const supplied = decodeBase64Url(encodedSignature);
  const expected = crypto.createHmac("sha256", secret).update(encodedPayload).digest();
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    throw new Error("Invalid signed_request signature");
  }

  return payload;
}

function readSignedRequest(req) {
  if (req.body && typeof req.body === "object") return req.body.signed_request;
  if (typeof req.body === "string") return new URLSearchParams(req.body).get("signed_request");
  return undefined;
}

export default function handler(req, res) {
  if (req.method === "GET") {
    return res.status(200).json({
      service: "PagePilot Meta data deletion callback",
      status: "ready"
    });
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const secret = process.env.META_APP_SECRET;
  if (!secret) return res.status(503).json({ error: "Callback is not configured" });

  try {
    const payload = parseSignedRequest(readSignedRequest(req), secret);
    if (!payload.user_id) throw new Error("The request contains no user_id");

    const confirmationCode = crypto.randomBytes(16).toString("hex");
    const baseUrl = `https://${req.headers.host}`;

    // PagePilot currently stores its working data only on the owner's computer.
    // The status page explains how the verified request is completed locally.
    return res.status(200).json({
      url: `${baseUrl}/deletion-status.html?code=${confirmationCode}`,
      confirmation_code: confirmationCode
    });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
}
