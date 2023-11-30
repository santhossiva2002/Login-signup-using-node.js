const express = require('express');
const app = express();
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const flash = require('connect-flash');
require('dotenv').config();
const cookieParser = require('cookie-parser');
app.use(cookieParser());

const { MONGO_URL, PORT, SESSION_SECRET } = process.env;

mongoose
  .connect(MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('MongoDb is connected successfully'))
  .catch((err) => console.error('MongoDb connection error:', err));

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: true }));
app.use(flash());

// Sample User model
const User = mongoose.model('User', {
  username: String,
  password: String,
  email: String,
});

app.get('/signup', (req, res) => {
    res.render('signup', { message: req.flash('error') });
  });
  app.post('/signup', async (req, res) => {
    try {
      const { username, password, email } = req.body;
  
      // Check if the username already exists
      const existingUser = await User.findOne({  email });
  
      if (existingUser) {
        req.flash('error', 'Username or email already exists. Please choose a different username or email.');
        return res.redirect('/signup');
      }
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Create a new user
      const user = new User({
        username,
        password: hashedPassword,
        email,
      });
  
      // Save the user to the database
      await user.save();
  
      // Redirect to login after successful signup
      res.redirect('/login');
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
    }
  });
  

// Login route
app.get('/login', (req, res) => {
  res.render('login', { message: req.flash('error') });
});

app.post('/login', async (req, res) => {
    try {
      const { email, password } = req.body;
  
      // Find the user by username
      const user = await User.findOne({ email });
  
      if (!user) {
        req.flash('error', 'Invalid username or password');
        return res.redirect('/login');
      }
  
      // Check the password
      const isPasswordValid = await bcrypt.compare(password, user.password);
  
      if (!isPasswordValid) {
        req.flash('error', 'Invalid username or password');
        return res.redirect('/login');
      }
  
      // Generate a JWT token
      const token = jwt.sign({ userId: user._id }, 'secret_key', { expiresIn: '1h' });
  
      // Set the token in the cookie
      res.cookie('token', token);
  
      // Redirect to the index page after successful login
      res.redirect('/');
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
    }
  });
  

// Authentication middleware
// Authentication middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.redirect('/login');
  }

  jwt.verify(token, 'secret_key', async (err, decoded) => {
    if (err) {
      return res.redirect('/login');
    }

    try {
      const user = await User.findById(decoded.userId);
      if (!user) {
        return res.redirect('/login');
      }

      req.user = { userId: decoded.userId, username: user.username };
      next();
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
    }
  });
};

  
  // Logout route
  app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
  });

  app.get('/signup',(req,res)=>{
    req.redirect('/signup')
  })

 // Index route (protected by authentication)
app.get('/', authenticateToken, (req, res) => {
    res.render('index', { username: req.user.username }); // Pass the username to the template
  });
  

app.listen(PORT, () => {
  console.log(`Server is listening on ${PORT}`);
});
