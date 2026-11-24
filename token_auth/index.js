const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');

process.loadEnvFile(path.join(__dirname, '../.env'));

const port = 3003;
const SESSION_KEY = 'Authorization';
const { AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET } = process.env;

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use((req, res, next) => {
  const token = req.get(SESSION_KEY);
  req.session = {};

  if (token) {
    const decoded = jwt.decode(token);

    if (decoded && decoded.exp * 1000 > Date.now()) {
      req.session = {
        username: decoded.email || decoded.nickname || decoded.sub,
        user: decoded,
      };
    }
  }

  next();
});

app.get('/', (req, res) => {
  if (req.session.username) {
    return res.json({
      username: req.session.username,
      logout: `http://localhost:${port}/logout`,
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

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
