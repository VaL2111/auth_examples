const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3003;
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';
const SECRET_KEY = 'secret_key';

app.use((req, res, next) => {
  const token = req.get(SESSION_KEY);

  try {
    req.session = jwt.verify(token, SECRET_KEY);
  } catch {
    req.session = {};
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

const users = [
  {
    login: 'Login',
    password: 'Password',
    username: 'Username',
  },
  {
    login: 'Login1',
    password: 'Password1',
    username: 'Username1',
  },
];

app.post('/api/login', (req, res) => {
  const { login, password } = req.body;

  const user = users.find((user) => {
    return user.login === login && user.password === password;
  });

  if (user) {
    const token = jwt.sign(
      { username: user.username, login: user.login },
      SECRET_KEY,
      { expiresIn: '1h' },
    );

    return res.json({ token });
  }

  res.status(401).send();
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
