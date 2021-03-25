const jwt = require('express-jwt');
const createError = require('http-errors');
const logger = require('./logger');

// JWT Validation Middleware. A user must have a valid bearer token.
// We expect to get JWT config details via the env.
function isAuthenticated() {
  return jwt({
    secret: process.env.SECRET,
    audience: process.env.JWT_AUDIENCE,
    issuer: process.env.JWT_ISSUER,
    // TODO: proper public/private key token signing
    algorithms: ['HS256'],
  });
}

// Determine whether the authorization options passed to isAuthorized are valid.
function validateAuthorizationOptions(options = {}) {
  let isValid = false;

  // It's possible that `roles` is defined, an array (roles) of strings with 1 or more values
  const { roles } = options;
  if (Array.isArray(roles) && roles.length && roles.every((role) => typeof role === 'string')) {
    isValid = true;
  }

  // It's possible that an authorizeUser() function is attached
  const { authorizeUser } = options;
  if (typeof authorizeUser === 'function') {
    isValid = true;
  }

  return isValid;
}

// Check to see if an already Authenticated user is Authorized to do something,
// based on: a) their role; b) arbitrary aspects of the user payload. For
// example, if a user must have the 'admin' role, or a user's `sub` claim
// must match an expected id. NOTE: isAuthorized() assumes (and depends upon)
// isAuthenticated() being called first.
function isAuthorized(options) {
  if (!validateAuthorizationOptions(options)) {
    throw new Error('invalid authorization options');
  }

  const { roles, authorizeUser } = options;

  return function (req, res, next) {
    if (!req.user) {
      next(createError(401, `no user or role info`));
      return;
    }

    // If these checks fail for any reason, return a 403
    try {
      const { user } = req;

      // If defined, check that all of the expected roles are present in this user's roles
      if (roles) {
        if (!user.roles) {
          next(createError(403, `user missing roles`));
          return;
        }
        for (const role of roles) {
          if (!user.roles.includes(role)) {
            next(createError(403, `user missing required role: ${role}`));
            return;
          }
        }
      }

      // If defined, check that the user's payload data matches what's expected
      if (authorizeUser) {
        if (!authorizeUser(user)) {
          next(createError(403, `user not authorized`));
          return;
        }
      }
    } catch (err) {
      logger.warn({ err }, 'Unexpected error authorizing user');
      next(createError(403, `user not authorized`));
      return;
    }

    // Authorized, let this proceed.
    next();
  };
}

// Default error handler
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  const status = err.status || 500;

  // Only log 500s
  if (status > 499) {
    logger.error({ err, req, res });
  }

  res.status(status);

  if (req.accepts('html')) {
    res.set('Content-Type', 'text/html');
    res.send(`<h1>${err.status} Error</h1><p>${err.message}</p>`);
  } else if (req.accepts('json')) {
    res.json({
      status: err.status,
      message: err.message,
    });
  } else {
    res.send(`${err.status} Error: ${err.message}\n`);
  }
}

function setHttpCacheHeaders(cacheObj) {
  /*
 Level 1 - No Caching at all
 Level 2 - Some caching, but for a small time window, 5 minutes
 Level 3 - Regular Caching, store them for a year
 Level 4 - Extreme Caching, store them forever
 */

  const options = cacheObj.options;
  const levelValue = cacheObj.level;
  const res = cacheObj.res;

  // Enum the levels for readability
  const levels = { LEVEL1: 1, LEVEL2: 2, LEVEL3: 3, LEVEL4: 4 };

  if (level === null && options === null) {
    next(
      createError(
        500,
        'You passed in arguments that are of type NULL. Make sure the objects exist before calling the function.'
      )
    );
  }

  //If we want to explicitly set a bunch of headers at once, without using the default levels.
  // Passed as a JSON Object with the following structure: {Cache-Control-Option : value }
  if (level === null || level === 0) {
    try {
      for (var key in options) {
        if (options.hasOwnProperty(key)) {
          r.set('${key}', '${options[key]}');
        }
      }
    } catch (error) {
      next(
        createError(
          500,
          "Unexpected Error: ${error}, check to see if you've made a mistake when defining options."
        )
      );
    }
  } else {
    switch (levelValue) {
      case LEVEL1:
        res.set('Cache-Control', 'public, max-age=0');
        break;
      case LEVEL2:
        res.set('Cache-Control', 'public, max-age=300');
        break;
      case LEVEL3:
        res.set('Cache-Control', 'public, max-age=2592000');
        break;
      case LEVEL4:
        res.set('Cache-Control', 'public, max-age=31536000, immutable');
        break;
    }
    //Add any additional options left over from the user.
    if (options != null) {
      try {
        for (var key in options) {
          if (options.hasOwnProperty(key)) {
            r.set('${key}', '${options[key]}');
          }
        }
      } catch (error) {
        next(
          createError(
            500,
            "Unexpected Error: ${error}, check to see if you've made a mistake when defining options."
          )
        );
      }
    }
  }
}
module.exports.isAuthenticated = isAuthenticated;
module.exports.isAuthorized = isAuthorized;
module.exports.errorHandler = errorHandler;
module.exports.setHttpCacheHeaders = setHttpCacheHeaders;
