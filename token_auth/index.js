const crypto = require('crypto');
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');

process.loadEnvFile(path.join(__dirname, '../.env'));

const port = 3003;
const REDIRECT_URI = `http://localhost:${port}`;
const SESSION_KEY = 'Authorization';
const REFRESH_HEADER_KEY = 'x-refresh-token';
const REFRESH_THRESHOLD_SECONDS = 300;
const {
  AUTH0_DOMAIN,
  AUTH0_CLIENT_ID,
  AUTH0_CLIENT_SECRET,
  JWT_ENCRYPTION_KEY,
} = process.env;

const ENCRYPTION_KEY = Buffer.from(JWT_ENCRYPTION_KEY || '', 'hex');

if (ENCRYPTION_KEY.length !== 32) {
  throw new Error(
    'JWT_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)',
  );
}

let cachedPublicKey = null;

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

function encryptJwsToJwe(jwsToken) {
  const headerB64 = Buffer.from(
    JSON.stringify({ alg: 'dir', enc: 'A256GCM', cty: 'JWT' }),
  ).toString('base64url');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  cipher.setAAD(Buffer.from(headerB64, 'ascii'));

  const ciphertext = Buffer.concat([
    cipher.update(jwsToken, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return `${headerB64}..${iv.toString('base64url')}.${ciphertext.toString('base64url')}.${authTag.toString('base64url')}`;
}

function decryptJweToJws(jweToken) {
  const parts = jweToken.split('.');

  if (parts.length !== 5 || parts[1] !== '') {
    throw new Error('Invalid JWE compact serialization format');
  }

  const [headerB64, , ivB64, ciphertextB64, authTagB64] = parts;
  const header = JSON.parse(
    Buffer.from(headerB64, 'base64url').toString('utf8'),
  );

  if (header.alg !== 'dir' || header.enc !== 'A256GCM') {
    throw new Error('Unsupported JWE algorithm');
  }

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    ENCRYPTION_KEY,
    Buffer.from(ivB64, 'base64url'),
  );
  decipher.setAAD(Buffer.from(headerB64, 'ascii'));
  decipher.setAuthTag(Buffer.from(authTagB64, 'base64url'));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertextB64, 'base64url')),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

async function getAuth0PublicKey() {
  if (cachedPublicKey) {
    return cachedPublicKey;
  }

  const response = await fetch(`https://${AUTH0_DOMAIN}/pem`);

  if (!response.ok) {
    throw new Error(
      `Failed to fetch Auth0 PEM certificate: ${response.status}`,
    );
  }

  cachedPublicKey = await response.text();
  return cachedPublicKey;
}

function verifyAuth0Token(token, publicKey, ignoreExpiration) {
  return jwt.verify(token, publicKey, {
    algorithms: ['RS256'],
    issuer: `https://${AUTH0_DOMAIN}/`,
    audience: AUTH0_CLIENT_ID,
    ignoreExpiration,
  });
}

async function refreshAuth0Token(refreshToken) {
  const response = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: AUTH0_CLIENT_ID,
      client_secret: AUTH0_CLIENT_SECRET,
      refresh_token: refreshToken,
    }),
  });

  if (!response.ok) {
    return null;
  }

  return response.json();
}

app.use(async (req, res, next) => {
  const encryptedToken = req.get(SESSION_KEY);
  const refreshToken = req.get(REFRESH_HEADER_KEY);
  req.session = {};

  if (encryptedToken) {
    try {
      let jwsToken = decryptJweToJws(encryptedToken);
      const publicKey = await getAuth0PublicKey();
      let decoded = verifyAuth0Token(jwsToken, publicKey, true);

      const nowInSeconds = Math.floor(Date.now() / 1000);
      const timeLeft = decoded.exp - nowInSeconds;

      if (timeLeft < REFRESH_THRESHOLD_SECONDS && refreshToken) {
        try {
          const refreshedData = await refreshAuth0Token(refreshToken);

          if (refreshedData && refreshedData.id_token) {
            jwsToken = refreshedData.id_token;
            decoded = verifyAuth0Token(jwsToken, publicKey, false);
            req.newToken = encryptJwsToJwe(jwsToken);
            console.log('Token refreshed successfully via refresh_token grant');
          }
        } catch (refreshError) {
          console.error('Failed to refresh token:', refreshError);
        }
      }

      if (decoded.exp > nowInSeconds) {
        req.session = {
          username: decoded.email || decoded.nickname || decoded.sub,
          user: decoded,
        };
      }
    } catch (error) {
      console.warn('JWT validation failed:', error.message);
    }
  }

  next();
});

app.get('/', (req, res) => {
  if (req.session.username) {
    return res.json({
      username: req.session.username,
      logout: `http://localhost:${port}/logout`,
      token: req.newToken,
    });
  }
  res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/login', (req, res) => {
  const authorizeParams = new URLSearchParams({
    client_id: AUTH0_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    response_mode: 'query',
    scope: 'openid profile email offline_access',
  });

  res.redirect(
    `https://${AUTH0_DOMAIN}/authorize?${authorizeParams.toString()}`,
  );
});

app.get('/logout', (req, res) => {
  const logoutParams = new URLSearchParams({
    client_id: AUTH0_CLIENT_ID,
    returnTo: REDIRECT_URI,
  });

  res.redirect(`https://${AUTH0_DOMAIN}/v2/logout?${logoutParams.toString()}`);
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
