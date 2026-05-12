// --- Lightweight TOTP Verifier ---
function base32ToBuffer(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, index = 0;
  const output = new Uint8Array(Math.ceil((base32.length * 5) / 8));
  for (let i = 0; i < base32.length; i++) {
    const char = base32[i].toUpperCase();
    if (char === '=') break;
    const val = alphabet.indexOf(char);
    if (val === -1) throw new Error('Invalid base32 character');
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }
  return output.buffer.slice(0, index);
}

async function generateHOTP(secretBuffer, counter) {
  const counterBuffer = new ArrayBuffer(8);
  new DataView(counterBuffer).setUint32(4, counter, false); 
  const key = await crypto.subtle.importKey('raw', secretBuffer, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, counterBuffer);
  const hash = new Uint8Array(signature);
  const offset = hash[19] & 0xf;
  const code = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
  return (code % 1000000).toString().padStart(6, '0');
}

async function verifyTOTP(userCode, base32Secret) {
  const secretBuffer = base32ToBuffer(base32Secret);
  const currentCounter = Math.floor(Date.now() / 1000 / 30);
  const codeCurrent = await generateHOTP(secretBuffer, currentCounter);
  const codePrevious = await generateHOTP(secretBuffer, currentCounter - 1);
  return userCode === codeCurrent || userCode === codePrevious;
}

// --- Main Worker Logic ---
export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key",
    };

    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

    try {
      // 1. DETERMINE AUTHENTICATION MODE
      const userProvidedKey = request.headers.get("X-API-Key");
      const authHeader = request.headers.get("Authorization");
      let activeApiKey = "";

      if (userProvidedKey) {
        // MODE A: Bring Your Own Key (BYOK)
        activeApiKey = userProvidedKey;
      } else if (authHeader && authHeader.startsWith("Bearer ")) {
        // MODE B: Authenticator (TOTP)
        const userCode = authHeader.split(" ")[1];
        const isValid = await verifyTOTP(userCode, env.TOTP_SECRET);
        
        if (!isValid) {
          return new Response(JSON.stringify({ error: "Invalid or expired Authenticator code." }), { status: 401, headers: { "Content-Type": "application/json", ...corsHeaders } });
        }
        activeApiKey = env.GOOGLE_API_KEY; // Use the secure server key
      } else {
         return new Response(JSON.stringify({ error: "Missing authentication. Provide an API Key or TOTP code." }), { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders } });
      }

      // 2. PROCESS GOOGLE API REQUEST
      if (request.method !== "POST") throw new Error("Only POST methods allowed.");
      const data = await request.json();
      
      const discRes = await fetch("https://trends.googleapis.com/$discovery/rest?version=v1beta");
      const discDoc = await discRes.json();
      const endpoint = `${discDoc.rootUrl}${discDoc.methods.getTimelinesForHealth.flatPath}`;

      const url = new URL(endpoint);
      url.searchParams.append("key", activeApiKey); // Use whichever key was authorized above
      
      const terms = data.terms.split(',').map(t => t.trim());
      terms.forEach(t => url.searchParams.append("terms", t));
      
      url.searchParams.append("timelineResolution", data.resolution || "week");
      url.searchParams.append("time.startDate", data.start);
      url.searchParams.append("time.endDate", data.end);
      url.searchParams.append("geoRestriction.country", data.geo || "US");

      const googleRes = await fetch(url.toString());
      const googleData = await googleRes.json();

      return new Response(JSON.stringify(googleData), {
        status: googleRes.status,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } });
    }
  }
};
