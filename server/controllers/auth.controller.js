import jwt from 'jsonwebtoken';
import config from '../../config/config';
// import crypto from 'crypto';

const User = require('../models/user.model');

/**
 * setUserInfo - sets user info from request body
 *
 * @param  {type} request express request object
 * @return {type}         null
 */
function setUserInfo(request) {
  return {
    _id: request._id,
    firstName: request.profile.firstName,
    lastName: request.profile.lastName,
    email: request.email,
    role: request.role,
  };
}

/**
 * generateToken - generates a unique jwt
 *
 * @param  {type} user user object (req.user)
 * @return {type}      jwt.sign() function
 */
function generateToken(user) {
  return jwt.sign(user, config.jwtSecret, {
    expiresIn: 10080 // in seconds
  });
}

/**
 * Returns jwt token if valid username and password is provided
 * @param req
 * @param res
 * @param next
 * @returns {*}
 */
function login(req, res) {
  const userInfo = setUserInfo(req.user);

  res.status(200).json({
    token: `JWT ${generateToken(userInfo)}`,
    user: userInfo
  });
}

function register(req, res, next) {
  // Check for registration errors
  const email = req.body.email;
  const firstName = req.body.firstName;
  const lastName = req.body.lastName;
  const password = req.body.password;

  // Return error if no email provided
  if (!email) {
    return res.status(422).send({ error: 'You must enter an email address.' });
  }

  // Return error if full name not provided
  if (!firstName || !lastName) {
    return res.status(422).send({ error: 'You must enter your full name.' });
  }

  // Return error if no password provided
  if (!password) {
    return res.status(422).send({ error: 'You must enter a password.' });
  }

  User.findOne({ email }, (err, existingUser) => {
    if (err) {
      return next(err);
    }

    // If user is not unique, return error
    if (existingUser) {
      return res.status(422).send({ error: 'That email address is already in use.' });
    }

    // If email is unique and password was provided, create account
    const user = new User({
      email,
      password,
      profile: { firstName, lastName }
    });

    user.save((error, savedUser) => {
      if (error) { return next(err); }

      // Subscribe member to Mailchimp list
      // mailchimp.subscribeToNewsletter(user.email);

      // Respond with JWT if user was created

      const userInfo = setUserInfo(savedUser);

      res.status(201).json({
        token: `JWT ${generateToken(userInfo)}`,
        user: userInfo
      });
    });
  });
}

export default { login, register };
