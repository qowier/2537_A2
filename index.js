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

app.get('/', (req,res) => {
  if (!req.session.authenticated) {
    const links = `
      <a href="/signup"><button>Sign Up</button></a>
      <a href="/login"><button>Log In</button></a>
    `;
    const html = `
      <div>
        <h1>Welcome to the Home site!</h1>
        <p>Please sign up or log in</p>
        <div>${links}</div>
      </div>
    `;
    res.send(html);
  }
  else {
    const links = `
      <a href="/members"><button>Members Area</button></a>
      <a href="/logout"><button>Log Out</button></a>
    `;
    const html = `
      <div>
        <h1>Hello, ${req.session.username}!</h1>
        <p>Welcome to the Members area.</p>
        <div>${links}</div>
      </div>
    `;
    res.send(html);
  }
});

app.get('/signup', (req, res) => {
  var html = `
    <h2>Signup:</h2>
    <form action='/submitSignup' method='POST'>
      <input type='text' name='username' placeholder='Username'/>
      <br>
      <input type='email' name='email' placeholder='Email'/>
      <br>
      <input type='password' name='password' placeholder='Password'/>
      <br>
      <button>Submit</button>
    </form>
    <a href="/"><button>Return Home</button></a>
    `;
    res.send(html);
});

app.post('/submitSignup', async (req,res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  //Empty field check
  if (!username || !email || !password) {
    var errorMsg = "";
    if (!username) {
      errorMsg += "Username is required.<br>";
    }
    if (!email) {
      errorMsg += "Email is required.<br>";
    }
    if (!password) {
      errorMsg += "Password is required.<br>";
    }
    var html = `${errorMsg}<a href="/signup"><button>Try Again</button></a>`;
    res.status(400).send(html);
    return;
  } else {
    const schema = Joi.object(
      {
        username: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
      });
    
      const validationResult = schema.validate({username, email,password});
      if (validationResult.error != null) {
        console.log(validationResult.error);
        var html = `
        ${validationResult.error}
        <br>
        <a href="/signup"><button>Try Again</button></a>`;
        res.status(400).send(html);
        return;
      }
    
      var hashedPassword = await bcrypt.hash(password, saltRounds);
    
      await userCollection.insertOne({username: username, email: email, password: hashedPassword});
      const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();
      req.session.authenticated = true;
      req.session.username = result[0].username;
      req.session.email = email;
      req.session.cookie.maxAge = expireTime;
      res.redirect("/members");
  }
});

app.get('/login', (req,res) => {
  var html = `
  <h2>Log In</h2>
  <form action='/loggingin' method='post'>
    <input type='email' name='email' placeholder='Email'/>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <button>Submit</button>
  </form>
  <br>
  <a href="/"><button>Return Home</button></a>
  `;
  res.send(html);
});

app.post('/loggingin', async (req,res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().email().required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	  console.log(validationResult.error);
    var html = `
    ${validationResult.error}
    <br>
    <a href="/login"><button>Try Again</button></a>`;
    res.status(400).send(html);
    return;
	}

  const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();

  if (result.length != 1) {
		console.log("user not found");
    var html = `
      <p>Invalid email/password combination.</p>
      <form action = "/login">
        <button>Try again</button>
      </form>
      <br>
      <a href= "/"><button>Return Home</button></a>
    `;
    res.send(html);
		return;
	}

  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
    return;
	}
	else {
    console.log("incorrect password");
    var html = `Invalid email/password combination.<br>
    <a href="/login"><button>Try Again</button></a>`;
    res.status(400).send(html);
    return;
	}
});

app.get('/members', (req,res) => {
  if (!req.session.authenticated) {
    res.redirect('/');
  }

  var username = req.session.username;
  var gif;
  const randomNum = Math.floor(Math.random() * 10000) + 1;

  if (randomNum >= 1 && randomNum < 3000) {
    gif = "<img src='/shake.gif' style='width:500px;'>";
  }
  else if (randomNum >= 3000 && randomNum < 6000) {
    gif ="<img src='/eat_popcorn.gif' style='width:500px;'>";
  }
  else if (randomNum >= 6000 && randomNum <= 9000) {
    gif = "<img src='/rick_roll.gif' style='width:500px;'>";
  }
  else if (randomNum > 9000) {
    gif ="<img src='/over_9000.gif' style = 'width:500px;'>";
  }

  var html = `
    <h2> Hello, ${username}! </h2>
    <h2>Welcome to the Members Area!</h2>
    <br>
    ${gif}
    <br>
    <a href="/"><button>Return Home</button></a>
    <br>
    <a href="/logout"><button>Log Out</button></a>`;
  res.send(html);
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

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
  var color = req.query.color;
  res.send("<h1 style='color:" + color + ";'>Welcome to the about page!!</h1>");
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port " + port);
}); 
