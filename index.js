require('dotenv').config();
const express = require('express');
const app = express();
const session = require('express-session');
const mongoStore = require('connect-mongo');
const mongoStoreSession = require('connect-mongodb-session');
const bcrypt = require('bcrypt')
const j = require('joi');
const saltRounds = 16;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const expireTime = 24 * 60 * 60 * 1000;

const port = process.env.PORT || 3000;

var {database} = require(__dirname + '/dbConnection.js');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var dbStore = mongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({
  secret: node_session_secret,
	store: dbStore,
	saveUninitialized: false, 
	resave: true
}));

app.get('/', (req, res) => {
  res.send(`
    <h2>Welcome!</h2>
    <form action="/login" method="GET"><button type="submit">Log In</button></form>
    <form action="/signup" method="GET"><button type="submit">Sign Up</button></form>
  `);
});

app.get('/signup', (req, res) => {
  res.send(`
    <h2>Sign Up</h2>
      <form action="/signUpPost" method="POST">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username" placeholder="Enter your username">
        <br>
        <label for="email">Email:</label><br>
        <input type="text" id="email" name="email" placeholder="Enter your email">
        <br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" placeholder="Enter your password">
        <br>
        <input type="submit" value="Sign Up">
        </form>
  `);
});

app.get('/login', (req, res) => {
  res.send(`
    <h2>Login</h2>
      <form action="/loginPost" method="POST">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" placeholder="Enter your username">
    
          <label for="password">Password</label>
          <input type="password" id="password" name="password" placeholder="Enter your password">
    
          <input type="submit" value="Login">
        </form>
  `);
});

app.post('/signUpPost', async (req,res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;
  const missingUsername = (username === '');
  const missingEmail = (email ===  '');
  const missingPassword = (password === '');

  if (missingEmail || missingPassword || missingUsername) {
    let missingFields = [];
    if (missingUsername) { missingFields = missingFields.concat('username'); }
    if (missingEmail) { missingFields = missingFields.concat('email'); }
    if (missingPassword) { missingFields = missingFields.concat('password'); }

    const message = `Missing ${missingFields.join(', ')} field(s), please try again!`;
    res.redirect(`/signUpFail?message=${encodeURIComponent(message)}`);
  } else {
  const schema = j.object({
			username: j.string().min(1).alphanum().required(),
      email: j.string().min(1).email().required(),
			password: j.string().min(1).required()
		});

    const validateInput = schema.validate({username, email, password});
    if (validateInput.error != null) {
       console.log(validateInput.error);
       res.redirect("/signup");
       return;
    }

    var pwHashed = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({username: username, email: email, password: pwHashed});
    req.session.authenticated = true;
    req.session.username = username;
    res.redirect('/loggedin');
  }
});

app.post('/loginPost', async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  const schema = j.string().required()
  const validateInput = schema.validate(username);
  if (validateInput.error != null) {
    console.log(validateInput.error);
    res.redirect("/loginFail");
    return;
  }

  const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("Can't find user.")
    res.redirect("/loginFail");
    return;
  }

  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/loggedIn');
    return;
  }
  else {
    console.log("Incorrect Password!");
    res.redirect("/loginFail");
    return;
  }
  });

  app.get('/signUpFail', (req, res) => {
    const message = req.query.message;
    res.send(`
      <h2>${message}</h2>
      <a href="/signup">Try Again</a>
    `);
  });

  app.get('/loginFail', (req,res) =>{
    res.send(`
      <h2>Invalid Username/Password combination, please try again!</h2>
      <a href="/login">Try Again</a>
    `);
});

app.get('/loggedin', (req, res) => {
  const auth = req.session.authenticated;
  const username = req.session.username;
  if(!auth) {
    res.redirect('/');
  } else {
    res.send(`
    <h2>Hello, ${username}!</h2>
    <form action="/members" method="GET"><button type="submit">Go to Members Area</button></form>
    <form action="/logout" method="POST"><button type="submit">Sign Out</button></form>
    `);
  }
})

app.get('/members', (req, res) => {
  const auth = req.session.authenticated;
  const username = req.session.username;
  if(!auth) {
    res.redirect("/");
  } else {
    const randomImage = Math.floor(Math.random() * 3) + 1;
    res.send(`
      <h2>Hello, ${username}!</h2>
      <img src="/frog${randomImage}.png" alt="Frogs :)">
      <form action="/logout" method="POST"><button type="submit">Sign Out</button></form>
    `);
  }
});

app.use(express.static(__dirname + "/public"));

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('*', (req,res) =>{
  res.status(404);
  res.send(`Page not found - 404`);
});

app.listen(3000, function() {
  console.log('Server started on port 3000');
});
