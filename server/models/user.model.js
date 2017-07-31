import Promise from 'bluebird';
import mongoose from 'mongoose';
import httpStatus from 'http-status';
import bcrypt from 'bcrypt-nodejs';
import APIError from '../helpers/APIError';

const Schema = mongoose.Schema;

/**
 * User Schema
 */
const UserSchema = new Schema({
  email: {
    type: String,
    lowercase: true,
    unique: true,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  profile: {
    firstName: {
      type: String
    },
    lastName: {
      type: String
    }
  },
  role: {
    type: String,
    enum: [
      'Member', 'Client', 'Owner', 'Admin'
    ],
    default: 'Member'
  },
  resetPasswordToken: {
    type: String
  },
  resetPasswordExpires: {
    type: Date
  }
},
  { timestamps: true }
);

/**
 * Add your
 * - pre-save hooks
 * - validations
 * - virtuals
 */

/**
 * Methods
 */
UserSchema.method({});

// Method to compare password for login
UserSchema.methods.comparePassword = function (candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
    if (err) {
      return cb(err);
    }
    cb(null, isMatch);
  });
};

/**
 * Statics
 */
UserSchema.statics = {
  /**
   * Get user
   * @param {ObjectId} id - The objectId of user.
   * @returns {Promise<User, APIError>}
   */
  get(id) {
    return this
      .findById(id)
      .exec()
      .then(function (user) {
        if (user) {
          return user;
        }

        const err = new APIError('No such user exists!', httpStatus.NOT_FOUND);
        return Promise.reject(err);
      });
  },

  /**
   * List users in descending order of 'createdAt' timestamp.
   * @param {number} skip - Number of users to be skipped.
   * @param {number} limit - Limit number of users to be returned.
   * @returns {Promise<User[]>}
   */
  list({ skip = 0, limit = 50 } = {}) {
    return this
    .find()
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .exec();
  }
};


/**
 * UserSchema - pre save hook
 *
 * @param  {type} 'save'        save validation for user
 * @param  {type} function(next) next middleware function
 * @return {type}               returns user model this
 */
UserSchema.pre('save', function (next) {
  const user = this;
  const SALT_FACTOR = 9;

  if (!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_FACTOR, (error, salt) => {
    if (error) return next(error);

    bcrypt.hash(user.password, salt, null, (err, hash) => {
      if (err) return next(err);
      user.password = hash;
      return next();
    });
  });
});

/**
 * @typedef User
 */
export default mongoose.model('User', UserSchema);
