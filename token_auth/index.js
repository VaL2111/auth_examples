const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');

process.loadEnvFile(path.join(__dirname, '../.env'));

const port = 3003;
const SESSION_KEY = 'Authorization';
const REFRESH_HEADER_KEY = 'x-refresh-token';
const REFRESH_THRESHOLD_SECONDS = 300;
const { AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET } = process.env;

let cachedPublicKey = null;

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

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

async function getManagementApiToken() {
  const response = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: AUTH0_CLIENT_ID,
      client_secret: AUTH0_CLIENT_SECRET,
      audience: `https://${AUTH0_DOMAIN}/api/v2/`,
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to obtain Management API token');
  }

  const data = await response.json();
  return data.access_token;
}

app.use(async (req, res, next) => {
  let token = req.get(SESSION_KEY);
  const refreshToken = req.get(REFRESH_HEADER_KEY);
  req.session = {};

  if (token) {
    try {
      const publicKey = await getAuth0PublicKey();
      let decoded = verifyAuth0Token(token, publicKey, true);

      const nowInSeconds = Math.floor(Date.now() / 1000);
      const timeLeft = decoded.exp - nowInSeconds;

      if (timeLeft < REFRESH_THRESHOLD_SECONDS && refreshToken) {
        try {
          const refreshedData = await refreshAuth0Token(refreshToken);

          if (refreshedData && refreshedData.id_token) {
            token = refreshedData.id_token;
            decoded = verifyAuth0Token(token, publicKey, false);
            req.newToken = token;
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

app.get('/logout', (req, res) => {
  res.redirect('/');
});

app.post('/api/login', async (req, res) => {
  const { login, password } = req.body;

  try {
    const response = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
        realm: 'Username-Password-Authentication',
        username: login,
        password: password,
        client_id: AUTH0_CLIENT_ID,
        client_secret: AUTH0_CLIENT_SECRET,
        scope: 'openid profile email offline_access',
      }),
    });

    if (!response.ok) {
      return res.status(401).send();
    }

    const data = await response.json();

    return res.json({
      token: data.id_token,
      refreshToken: data.refresh_token,
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).send();
  }
});

app.post('/api/register', async (req, res) => {
  const { login, password } = req.body;

  try {
    const managementToken = await getManagementApiToken();

    const response = await fetch(`https://${AUTH0_DOMAIN}/api/v2/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${managementToken}`,
      },
      body: JSON.stringify({
        email: login,
        password: password,
        connection: 'Username-Password-Authentication',
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        message: data.message || 'Registration failed',
      });
    }

    return res.status(201).json({
      user_id: data.user_id,
      email: data.email,
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
