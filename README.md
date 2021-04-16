# Satellite

![node-js-ci](https://github.com/Seneca-CDOT/satellite/workflows/node-js-ci/badge.svg)

A Microservice Framework for [Telescope](https://github.com/Seneca-CDOT/telescope).
Because Ray said we should try microservices!

Satellite creates an [Express.js](http://expressjs.com/) based server with
various common pieces already set up. Bring your own router and let us do the rest.

## Install

```
npm install --save @senecacdot/satellite
```

## Configure

You need to set the following environment variables if you want Elastic APM
monitoring for your service:

- `ELASTIC_APM_SERVER_URL`: the URL to the APM server (e.g., http://localhost:8200)
- `ELASTIC_APM_SERVICE_NAME`: the name of the service as it will appear in APM

If you don't provide these values in your environment, APM monitoring will be
disabled.

In addition, the following JWT verification values are required:

- `SECRET`: the secret used for JWT token verification
- `JWT_AUDIENCE`: the audience (aud) claim expected in JWT token verification
- `JWT_ISSUER`: the issuer (iss) claim expected in JWT token verification

## Usage

In its most basic form, a Satellite-based microservice looks like this:

```js
const {
  Satellite, // the Satellite constructor
  logger, // pre-configured logger
} = require('@senecacdot/satellite');

// Define your microservice
const service = new Satellite();

// Add your routes to the service's router
service.router.get('/my-route', (req, res) => {
  res.json({ message: 'hello world' });
});

// Start the service on the specified port
service.start(8888, () => {
  logger.info('Satellite Microservice running on port 8888');
});
```

### `Satellite(options)`

- `healthCheck`: an optional `function` returning a `Promise`, used to determine if the service is healthy. If no function is defined, a default one will be provided. The `healthCheck` function is what runs at the `/healthcheck` route by default.

```js
const service = new Satellite({
  healthCheck: async () => {
    // Connect to db and return a promise
    const ok = await doSomeAsyncTask();
    return ok;
  },
});
```

- `shutDown`: an optional `function` returning a `Promise`, used to run any shutdown logic (sync or async) before the server is shut down. If no function is defined, a default one will be provided.

```js
// Open connections to Redis and Elasticsearch
const redis = Redis();
const elastic = Elastic();

const service = new Satellite({
  // On shut down, close the open connection to Redis and Elasticsearch
  shutDown: () => Promise.all([redis.quit(), elastic.close()]),
});
```

- `cors`: the options to pass to the [cors](https://www.npmjs.com/package/cors) middleware. By default all options are turned on. Use `cors: false` to disable cors.

- `helmet`: the options to pass to the [helmet](https://www.npmjs.com/package/helmet) middleware. By default all options are turned on. Use `helmet: false` to disable helmet.

- `beforeParsers`: an optional hook function that allows access to the `app` during creation prior to adding the body parsers

```js
const service = new Satellite({
  beforeParsers(app) {
    // Optionally add some middleware before the parser are attached
    app.use(myMiddlewareFunction());
  },
});
```

- `beforeRouter`: an optional hook function that allows access to the `app` during creation prior to adding the router.

```js
const service = new Satellite({
  beforeRouter(app) {
    // Optionally add some middleware before the router is attached
    app.use(myMiddlewareFunction());
  },
});
```

- `router`: an optional router to use in place of the default one created automatically.

```js
const myRouter = require('./router);

const service = new Satellite({
  router: myRouter
});
```

- `credentials`: an optional Object containing a `key` and `cert`, to be used in the creation of a secure HTTPS server. If `credentials` is not provided, an HTTP server is created instead (the default).

```js
const service = new Satellite({
  credentials: {
    key: fs.readFileSync('/path/to/privkey.pem'),
    cert: fs.readFileSync('/path/to/fullchain.pem'),
  },
});
```

There are also a number of optional objects and functions available to further
customize your service.

### Router()

Some services are easier to write using more than one router (e.g., defining
complex routes in their own files). This is easily done with the `Router`:

```js
// custom-router.js
const { Router } = require("@senecacdot/satellite");

const router = Router();

router.get('/custom-route', (req, res) => {...});
router.post('/custom-route', (req, res) => {...});
router.put('/custom-route', (req, res) => {...});
router.delete('/custom-route', (req, res) => {...});

module.exports = router;


// index.js
const { Satellite } = require("@senecacdot/satellite");
const router = require('./custom-router");

const service = new Satellite({
  // Use our custom router instead of the default router
  router
});
```

### Middleware

A number of middleware functions are available to help with your routes.

- `isAuthenticated()` - used to make sure that a request includes a valid JWT and the user has previously been authenticated.

```js
router.get('/private-route', isAuthenticated(), (req, res) => {...});
```

- `isAuthorized()` - used to check if an authenticated user is authorized. NOTE: `isAuthorized()` must be used in conjunction with `isAuthenticated()`:

Here are some examples:

```js
const { isAuthenticated, isAuthorized } = require("@senecacdot/satellite");

// Authorize based on arbitrary user claims
router.post(
  '/:user',
  isAuthenticated(),
  isAuthorized(
    // `user` is the decoded payload of the user's token.  Here we use it
    // to make sure that the user param matches the user's `sub` claim,
    // or that the user is an admin.
    (req, user) => {
      // Check if the user making the request is the same one for the route
      if(user.sub === req.params.user) {
        return true;
      }

      // If not, check if they are an admin
      return user.roles.includes('admin');
    }
  ),
  (req, res) => {...}
);
```

### Logger

The `logger` object is a pre-configured logger based on [Pino](https://getpino.io/#/).

```js
const { logger } = require('@senecacdot/satellite');

logger.info('Hello World!');
```

### Hash

The `hash()` function is a convenience hashing function, which returns a 10 character hash:

```js
const { hash } = require('@senecacdot/satellite');

const id = hash('http://someurl.com');
```

### Create Service Token

Services authorize requests using the `isAuthenticated()` and `isAuthorized()` middleware discussed above.
For the most part, this is meant to be used for the case of user-to-service requests: an authenticated
user passes a JWT token (acquired via the `auth` service), and uses it to request authorization to some
protected route.

However, in cases where you need to do a service-to-service request, you can use the `createServiceToken()`
function in order to get a short-lived access token that will include the `"service"` role:

```js
const { createServiceToken } = require('@senecacdot/satellite');
...
const res = await fetch(`some/protected/route`, {
  headers: {
    Authorization: `bearer ${createServiceToken()}`,
  },
});
```

The receiving service can then opt-into allowing this service to be authorized by using
the `isAuthenticated()` and `isAuthorized()` middleware like so:

```js
const { isAuthenticated, isAuthorized } = require("@senecacdot/satellite");

// Allow requests with a token bearing the 'service' role to proceed
router.get('/admin-or-service', isAuthenticated(), isAuthorized({ roles: ["service"] }), (req, res) => {...});
```

### Create Error

The `createError()` function creates a unique HTTP Error Object which is based on [http-errors](https://www.npmjs.com/package/http-errors).

```js
const { createError } = require('@senecacdot/satellite');

const e = createError(404, 'This is a message that describes your Error object');

console.log(e.status); // of type: Number

console.log(e.message); // of type: String
```
