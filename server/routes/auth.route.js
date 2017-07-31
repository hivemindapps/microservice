import express from 'express';
// import validate from 'express-validation';
// import expressJwt from 'express-jwt';
import passport from 'passport';
// import paramValidation from '../../config/param-validation';
import authCtrl from '../controllers/auth.controller';

// import config from '../../config/config';

// Require passport setup
require('../../config/passport');

// Middleware to require login/auth
// const requireAuth = passport.authenticate('jwt', { session: false });
const requireLogin = passport.authenticate('local', { session: false });

const router = express.Router(); // eslint-disable-line new-cap
// const passportService = require('../../config/passport');

router.post('/login', requireLogin, authCtrl.login);
router.post('/register', authCtrl.register);

/** GET /api/auth/random-number - Protected route,
 * needs token returned by the above as header. Authorization: Bearer {token} */

export default router;
