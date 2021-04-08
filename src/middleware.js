const jwt = require('express-jwt');
const createError = require('http-errors');
const logger = require('./logger');
const ms = require('ms');
const express = require('express');

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

function cache(res) {
  this.forever = (res) => {
    const t = ms('1y');
    res.headers.set(`Cache-Control`, `public, max-age=${t}, immutable`);
  }; // Forever Function

  /*
no-store is needed with max-age=0
we don't want to serve stale resources when Telescope is down.
see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control#requiring_revalidation
*/
  this.never = (res) => {
    res.headers.set('Cache-Control', 'public, no-store, max-age=0');
  };

  this.duration = (time, res) => {
    const t = ms(time);
    res.headers.set('Cache-Control', `public, max-age=${t}`);
  };

  this.staleFor = (time, res) => {
    if (res.headers.get('Cache-Control') !== null) {
      const t = ms(time);
      res.headers.append('Cache-Control', `max-stale=${t}`);
    } else {
      next(
        createError(
          428,
          'You do not have a Cache-Control header, this function is used for attributes that contain the header. '
        )
      );
    }
  };

  this.freshFor = (time, res) => {
    if (res.headers.get('Cache-Control') !== null) {
      const t = ms(time);
      res.headers.append('Cache-Control', `min-fresh=${t}`);
    } else {
      next(
        createError(
          428,
          'You do not have a Cache-Control header, this function is used for attributes that contain the header. '
        )
      );
    }
  };
  return {
    forever: this.forever,
    never: this.never,
    duration: this.duration,
    staleFor: this.staleFor,
    freshFor: this.freshFor,
  };
}
module.exports.isAuthenticated = isAuthenticated;
module.exports.isAuthorized = isAuthorized;
module.exports.errorHandler = errorHandler;
module.exports.cache = cache;
