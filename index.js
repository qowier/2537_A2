require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const port = process.env.PORT;

const app = express();
const Joi = require("joi");

//expire after 1 hour
const expireTime = 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
  secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

//Authentication
function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req,res,next) {
  if (isValidSession(req)) {
    next();
  }
  else {
    res.redirect('/login');
  }
}

//Authorization
function isAdmin(req) {
  if (req.session.user_type == 'admin') {
    return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("403");
    return;
  }
  else {
    next();
  }
}

app.get('/', (req,res) => {
  if (!req.session.authenticated) {
    res.render("index_no_auth");
  }
  else {
    res.render("index_auth", { username: req.session.username });
  }
});

app.get('/signup', (req, res) => {
  res.render("signup");
});

app.post('/submitSignup', async (req,res) => {
  const { username, email, password } = req.body;

  //Empty field check
  if (!username || !email || !password) {
    const errorMsg = [];

    if (!username) {
      errorMsg.push("Username is required");
    }
    if (!email) {
      errorMsg.push("Email is required");
    }
    if (!password) {
      errorMsg.push("Password is required");
    }
    res.status(400).render("signupError", { errorMsg : errorMsg.join('. ') });
    return;
  }

  const schema = Joi.object(
    {
      username: Joi.string().alphanum().max(20).required(),
      email: Joi.string().email().required(),
      password: Joi.string().max(20).required()
  });
  
  try {
    await schema.validateAsync({username, email, password});
  } catch (error) {
    console.log(error);
    res.status(400).render("signupError", { errorMsg: error});
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);
  try {
    await userCollection.insertOne({
      username, 
      email, 
      password: hashedPassword,
      user_type: "user"
    });
    req.session.authenticated = true;
    req.session.username = username;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
  } catch (error) {
    console.log(error);
    res.status(500).render("500");
  }
});

app.get('/login', (req,res) => {
  res.render("login");
});

app.post('/loggingin', async (req,res) => {
  const email = req.body.email;
  const password = req.body.password;
  const schema = Joi.string().email().required();
	const validationResult = schema.validate(email);

	if (validationResult.error != null) {
    res.status(400).render("400");
    return;
	}

  const result = await userCollection.find({email: email})
    .project({username: 1, email: 1, password: 1, user_type: 1, _id: 1})
    .toArray();

  //if user is not found
  if (result.length != 1) {
		res.status(400).render("400");
		return;
	}

  //If password entered is correct.
  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.email = email;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
    return;
	}
	else {
    res.status(400).render("400");
    return;
	}
});

app.use('/members', sessionValidation);
app.get('/members', (req,res) => {
  const randomNum = Math.floor(Math.random() * 10000) + 1;
  res.render("members", {username: req.session.username, randomNum});
});

app.get('/logout', (req,res) => {
	req.session.destroy();
  res.redirect('/');
});


app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({
    username: 1, 
    email: 1, 
    password: 1, 
    user_type: 1, 
    _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
  var color = req.query.color;
  res.render("about", {color: color});
});

app.get('/contact', (req,res) => {
  var missingEmail = req.query.missing;
  res.render("contact", {missing: missingEmail});
});

app.post('/submitContact', (req,res) => {
  var email = req.body.email;
  if (!email) {
    res.redirect('/contact?missing=1');
  }
  else {
    res.render("contactSuccess");
  }
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
  const result = await userCollection.find().project({username: 1, _id: 1, email: 1, user_type: 1}).toArray();
  res.render("admin", {users: result});
});

app.post('/admin', sessionValidation, adminAuthorization, async (req,res) =>{
  const { username, user_type } = req.body;
  await userCollection.updateOne({ username }, { $set: { user_type } });
  res.redirect('/admin');
});

//This is a tester function for testing pages. Keep commented unless needed
// app.get('/test', (req, res) => {
//   res.render("403");
// });

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404).render("404");
});

app.listen(port, () => {
	console.log("Node application listening on port " + port);
}); 
