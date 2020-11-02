const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

//User model
const User = require('../models/User');
const { forwardAuthenticated } = require('../config/auth');

// Login Page
router.get('/login', forwardAuthenticated, (req, res) => res.render('login'));

// Register Page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register'));

// Register Handle
router.post('/register', (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    // Check required fields
    if(!name || !email || !password || !password2) {
        errors.push({ msg: 'Fill Everything u DUMB' });
    }

    // Check password match
    if(password !== password2) {
        errors.push({ msg: 'Password not much DUMB' });
    }

    // Check pass length
    if(password.length < 6) {
        errors.push({ msg: 'Password cant less than 6 char DUMB'});
    }

    if(errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        // Validation
        User.findOne({ email: email })
            .then(user => {
                if(user) {
                    // User exists
                    errors.push({ msg: 'Email is already taken'});
                    res.render('register', {
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });
                } else {
                    const newUser = new User({
                        name,
                        email,
                        password
                    });

                    // Hash password
                    bcrypt.genSalt(10, (err, salt) => 
                    bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if(err) throw err;
                        //Set password
                        newUser.password = hash;
                        //Save user
                        newUser.save()
                            .then(user => {
                                req.flash('success_msg', 'You are part of us now')
                                res.redirect('/users/login');
                            })
                            .catch(err => console.log(err));
                    }))
                }
            })
    }
});

// Login
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
      successRedirect: '/dashboard',
      failureRedirect: '/users/login',
      failureFlash: true
    })(req, res, next);
});

// Logout
router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'you are logged out');
    res.redirect('/users/login');
});

module.exports = router;