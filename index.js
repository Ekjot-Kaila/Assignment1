require("./utils.js");

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  })
);

app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    return res.send(
      "<a href='/signup'>sign up</a> <br> <a href='/login'>login</a>  "
    );
  }
  var username = req.session.username;
  res.send(
    `Hello, ${username}! <br> <a href='/members'> Go to Members Area</a> <br> <a href='/logout'> Logout</a> `
  );
});

app.get("/nosql-injection", async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  //If we didn't use Joi to validate and check for a valid URL parameter below
  // we could run our userCollection.find and it would be possible to attack.
  // A URL parameter of user[$ne]=name would get executed as a MongoDB command
  // and may result in revealing information about all users or a successful
  // login without knowing the correct password.
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

app.get("/about", (req, res) => {
  var color = req.query.color;

  res.send("<h1 style='color:" + color + ";'>Patrick Guichon</h1>");
});

app.get("/contact", (req, res) => {
  var missingEmail = req.query.missing;
  var missingEmails = req.query.missings;
  var missingEmailss = req.query.missingss;
  var emailandpassword = req.query.ep;
  var emailandusername = req.query.eu;
  var usernameandpassword = req.query.up;
  var emailandusernameandpassword = req.query.eup;
  var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <input name='username' type='text' placeholder='username'>
            <input name='password' type='password' placeholder='password'>
            <button>Submit</button>
        </form>
    `;
  if (missingEmail) {
    html += "<br> email is required <br> <a href='/contact'>try again</a>";
  }
  if (missingEmails) {
    html += "<br> username is required <br> <a href='/contact'>try again</a>";
  }
  if (missingEmailss) {
    html += "<br> password is required <br> <a href='/contact'>try again</a>";
  }
  if (emailandpassword) {
    html +=
      "<br> email and password is required <br> <a href='/contact'>try again</a>";
  }
  if (emailandusername) {
    html +=
      "<br> username and email is required <br> <a href='/contact'>try again</a>";
  }
  if (usernameandpassword) {
    html +=
      "<br> password and username is required <br> <a href='/contact'>try again</a>";
  }
  if (emailandusernameandpassword) {
    html +=
      "<br> password,username and email is required <br> <a href='/contact'>try again</a>";
  }

  res.send(html);
});

app.post("/submitEmail", async (req, res) => {
  var email = req.body.email;
  var username = req.body.username;
  var password = req.body.password;
  if (!password && !username && !email) {
    return res.redirect("/contact?eup=1");
  }
  if (!email && !password) {
    return res.redirect("/contact?ep=1");
  }
  if (!username && !email) {
    return res.redirect("/contact?eu=1");
  }
  if (!password && !username) {
    return res.redirect("/contact?up=1");
  }
  if (!email) {
    return res.redirect("/contact?missing=1");
  }
  if (!username) {
    return res.redirect("/contact?missings=1");
  }
  if (!password) {
    return res.redirect("/contact?missingss=1");
  } else {
    res.send("Thanks for subscribing with your email: " + email);
  }
});

app.get("/signup", (req, res) => {
  var missingUsername = req.query.missing;
  var missingEmail = req.query.missings;
  var missingPassword = req.query.missingss;
  var emailandpassword = req.query.ep;
  var emailandusername = req.query.eu;
  var usernameandpassword = req.query.up;
  var emailandusernameandpassword = req.query.eup;
  var html = `
    Sign Up:
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <br>
    <input name='email' type='text' placeholder='email'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <button>Submit</button>
    </form>
    `;
  if (missingUsername) {
    html +=
      "<br> username is required <br> <a href='/signup'>try again</a>";
  }
  if (missingEmail) {
    html += "<br> email is required <br> <a href='/signup'>try again</a> ";
  }
  if (missingPassword) {
    html +=
      "<br> password is required <br> <a href='/signup'>try again</a> ";
  }
  if (emailandpassword) {
    html +=
      "<br> email and password is required <br> <a href='/signup'>try again</a>";
  }
  if (emailandusername) {
    html +=
      "<br> username and email is required <br> <a href='/signup'>try again</a>";
  }
  if (usernameandpassword) {
    html +=
      "<br> password and username is required <br> <a href='/signup'>try again</a>";
  }
  if (emailandusernameandpassword) {
    html +=
      "<br> password,username and email is required <br> <a href='/signup'>try again</a>";
  }

  res.send(html);
});

app.get("/login", (req, res) => {
  var missingUsername = req.query.missing;
  var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <button>Submit</button>
    </form>
    `;
  if (missingUsername) {
    html +=
      "<br> Invalid username/password combination <br> <a href='/login'>try again</a>";
  }
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var email = req.body.email;
  var username = req.body.username;
  var password = req.body.password;
  if (!password && !username && !email) {
    return res.redirect("/signup?eup=1");
  }
  if (!email && !password) {
    return res.redirect("/signup?ep=1");
  }
  if (!username && !email) {
    return res.redirect("/signup?eu=1");
  }
  if (!password && !username) {
    return res.redirect("/signup?up=1");
  }
  if (!username) {
    return res.redirect("/signup?missing=1");
  }
  if (!email) {
    return res.redirect("/signup?missings=1");
  }
  if (!password) {
    return res.redirect("/signup?missingss=1");
  } else {
    const schema = Joi.object({
      username: Joi.string().alphanum().max(20).required(),
      password: Joi.string().max(20).required(),
      email: Joi.string().email().required(),
    });

    const validationResult = schema.validate({ username, password, email });
    if (validationResult.error != null) {
      console.log(validationResult.error);
      res.redirect("/signup");
      return; 
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
      username: username,
      email: email,
      password: hashedPassword,
    });
    console.log("Inserted user");
    req.session.authenticated = true;
    req.session.username = username;
    
    var html = "successfully created user";
   // res.send(html);
   return res.redirect("/members") 
  }
});

app.post("/loggingin", async (req, res) => {
 // var username = req.body.username;
  var password = req.body.password;
  var email = req.body.email;
  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ email: 1, password: 1, username:1, _id: 1 })
    .toArray();

  
    
  console.log(result);
  if (result.length != 1) {
    console.log("user not found");
    res.redirect("/login?missing=1");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.cookie.maxAge = expireTime;
    
    res.redirect("/members");
    
  } else {
    console.log("incorrect password");
    res.redirect("/login?missing=1");
    return;
  }
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
     return res.redirect("/");
      
  }
  var username = req.session.username;
  var randomnumber = Math.floor(Math.random() * 3);
  if (randomnumber == 0) {
    res.send(`Hello, ${username}! <br>
     
      <br>
       <img src='/giphy2.gif' style='width:250px;'>
      <a href='/logout'> Logout</a>    
       `);
  }
  if (randomnumber == 1) {
    res.send(`Hello, ${username}! <br>
          
           <br>
            <img src='/giphy1.gif' style='width:250px;'>
           <a href='/logout'> Logout</a>    
            `);
  }
  if (randomnumber == 2) {
    res.send(`Hello, ${username}! <br>
              
               <br>
                <img src='/giphy.gif' style='width:250px;'>
               <a href='/logout'> Logout</a>    
                `);
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  // var html = `
  // You are logged out.
  // `;
  // res.send(html);
  res.redirect("/");
});

app.get("/cat/:id", (req, res) => {
  var bat = req.params.id;

  if (bat == 1) {
    res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
  } else if (bat == 2) {
    res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
  } else {
    res.send("Invalid cat id: " + bat);
  }
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.send("Page not found - 404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
