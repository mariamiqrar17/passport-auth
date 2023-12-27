if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const ejs = require("ejs");
const methodOverride = require('method-override');
const mongoose = require('mongoose');

// Import the User model
const User = require('./models/user');

const initializePassport = require('./passport-config');
initializePassport(
  passport,
  async email => {
    try {
      const user = await User.findOne({ email: email });
      return user;
    } catch (error) {
      console.error('Error finding user by email:', error);
      return null;
    }
  },
  id => User.findById(id)
);

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

app.get('/', checkAuthenticated, (req, res) => {
  res.render('index.ejs', { name: req.user.name });
});

app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login');
});

app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register');
});

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}));

app.post('/register', checkNotAuthenticated, async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    // Create a new user using the User model
    const user = new User({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword
    });

    // Save the user to the database
    await user.save();

    res.redirect('/login');
  } catch (error) {
    console.error('Error registering user:', error);
    res.redirect('/register');
  }
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  next();
}

app.delete('/logout', (req, res) => {
  req.logOut((error) => {
    if (error) {
      return next(error);
    }
    res.redirect('/login');
  });
});

// MongoDB connection
const DATABASE_URL = "mongodb+srv://mariam:12345@todoapp.ev0mwvc.mongodb.net/?retryWrites=true&w=majority";
const port = 3000;

mongoose.connect(DATABASE_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to MongoDB');

    // Start the Express server
    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  })
  .catch(err => {
    console.error('Error connecting to MongoDB:', err);
  });
