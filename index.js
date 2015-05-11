let express = require('express')
// let morgan = require('morgan')
let bodyParser = require('body-parser')
let cookieParser = require('cookie-parser')
let session = require('express-session')
let passport = require('passport')
let bcrypt = require('bcrypt')
let nodeifyit = require('nodeifyit')
let flash = require('connect-flash')
let mongoose = require('mongoose')
let User = require('./user')
let LocalStrategy = require('passport-local').Strategy
require('songbird')

const NODE_ENV = process.env.NODE_ENV
const PORT = process.env.PORT || 8000

let app = express()

app.set('view engine', 'ejs')

// Read cookies, required for sessions
app.use(cookieParser('ilovethenodejs'))

// Get POST/PUT body information (e.g., from html forms like login)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

// In-memory session support, required by passport.session()
app.use(session({
  secret: 'ilovethenodejs',
  resave: true,
  saveUninitialized: true
}))

// Use the passport middleware to enable passport
app.use(passport.initialize())

// Enable passport persistent sessions
app.use(passport.session())

app.use(express.static('public'))

app.use(flash())

passport.use(new LocalStrategy({
    // Use "email" field instead of "username"
    usernameField: 'email',
    failureFlash: true
}, nodeifyit(async (email, password) => {
   let user = await User.promise.findOne({email})

   if(!user || email !== user.email) {
       return [false, {message: 'Invalid username'}]
   }

   if (!await user.validatePassword(password)) {
       return [false, {message: 'Invalid password'}]
   }
   return user
}, {spread: true})))



passport.use('local-signup', new LocalStrategy({
    usernameField: 'email',
    failureFlash: true
  }, nodeifyit(async (email, password) => {
      email = (email || '').toLowerCase()
      if (await User.promise.findOne({email})) {
        return [false, {message: 'That email is already taken.'}]
      }

      // create the user
      let user = new User()
      user.email = email
      user.password = await user.generateHash(password)
      return await user.save()
  }, {spread: true})))

passport.serializeUser(nodeifyit(async (user) => user._id))

passport.deserializeUser(nodeifyit(async (id) => {
  return await User.promise.findById(id)
}))

function isLoggedIn(req, res, next) {
  if(req.isAuthenticated()) return next()
  res.redirect("/")
}

// routes
app.get('/', (req, res) => {
    res.render('index.ejs', {message: req.flash('error')})
})

app.get('/profile', isLoggedIn, (req, res) => {
    res.render('profile.ejs', {user: req.user,  message: req.flash('error')})
})

app.get('/logout', (req, res) => {
    req.logout()
    // res.render('profile.ejs', {message: req.flash('error')})
    res.redirect('/')
})

// process the login form
app.post('/login', passport.authenticate('local', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}))

app.post('/signup', passport.authenticate('local-signup', {
  successRedirect: '/profile',
  failureRedirect: '/',
  failureFlash: true
}))


// App starts here

mongoose.connect('mongodb://127.0.0.1:27017/authenticator')

app.listen(PORT, ()=> console.log(`Listening @ http://127.0.0.1:${PORT}`))

