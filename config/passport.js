const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');
const config = require('./config');
const User = require('../server/models/user.model');

const localOptions = {
  usernameField: 'email'
};

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeader(),
  secretOrKey: config.jwtSecret
};

// Setting up local login strategy
const localLogin = new LocalStrategy(localOptions, function (email, password, done) {
  User.findOne({
    email
  }, function (err, user) {
    if (err) {
      return done(err);
    }
    if (!user) {
      return done(null, false, { error: 'Your login details could not be verified. Please try again.' });
    }

    user.comparePassword(password, function (err2, isMatch) {
      if (err2) {
        return done(err2);
      }
      if (!isMatch) {
        return done(null, false, { error: 'Your login details could not be verified. Please try again.' });
      }

      return done(null, user);
    });
  });
});

// Setting up JWT login strategy
const jwtLogin = new JwtStrategy(jwtOptions, function (payload, done) {
  User.findById(payload._id, function (err, user) {
    if (err) {
      return done(err, false);
    }

    if (user) {
      done(null, user);
    } else {
      done(null, false);
    }
  });
});

passport.use(jwtLogin);
passport.use(localLogin);

export default { jwtLogin, localLogin };
