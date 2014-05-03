'use strict';

var TwitterStrategy = require('passport-twitter').Strategy
  , OAuth = require('oauth').OAuth
  ;

function getId(profile, cb) {
  if (!profile.id) {
    console.error(profile);
    throw new Error("user has no uinque identifier for which to save!");
  }

  cb(null, profile.id);
}

function getIds(profile) {
  var ids = []
    ;

  ids.push({ type: 'twitter', value: profile.id });

  return ids;
}

module.exports.init = function (passport, config, opts) {
  opts.Users.register('twitter', '1.0.0', getId, getIds);

  var oa
    , twitterAuthn
    , twitterAuthz
    , twConfig = config.twitter
    ;

  /*
  // TODO to allow this user to message you, follow us
  function directMessage(user, params, cb) {
    oa.post(
      "https://api.twitter.com/1.1/direct_messages/new.json"
    , user.twitter.token
    , user.twitter.tokenSecret
    , { "screen_name": params.sn, text: params.text }
    , cb
    );
  }
  */

  function initTwitterOauth() {
    oa = new OAuth(
      "https://twitter.com/oauth/request_token"
    , "https://twitter.com/oauth/access_token"
    , twConfig.consumerKey
    , twConfig.consumerSecret
    , "1.0A"
    , "http://" + config.host + "/authz/twitter/callback"
    , "HMAC-SHA1"
    );
  }
  initTwitterOauth();
  //module.exports.directMessage = directMessage;


  twitterAuthn = new TwitterStrategy({
      consumerKey: twConfig.consumerKey
    , consumerSecret: twConfig.consumerSecret
    , callbackURL: "http://" + config.host + "/authn/twitter/callback"
    },
    function(token, tokenSecret, profile, done) {
      console.log('[load:twN]');

      delete profile._raw;
      delete profile._json;
      done(null, {
        type: 'twitter'
      , fkey: profile.id
      , profile: profile
      , token: token
      , tokenSecret: tokenSecret
      });
    }
  );
  twitterAuthn.name = 'twitterAuthn';

  twitterAuthz = new TwitterStrategy({
      consumerKey: twConfig.consumerKey
    , consumerSecret: twConfig.consumerSecret
    , callbackURL: "http://" + config.host + "/authz/twitter/callback"
    , userAuthorizationURL: 'https://api.twitter.com/oauth/authorize'
    },
    function(token, tokenSecret, profile, done) {
      var authN
        ;

      console.log('[load:twZ]');

      delete profile._raw;
      delete profile._json;

      authN = {
        type: 'twitter'
      , fkey: profile.id
      , profile: profile
      , token: token
      , tokenSecret: tokenSecret
      // TODO a user may revoke authorization in the future without notification
      // This is preserved auth/users.js, but should have a callback instead
      , authorized: true
      };
      done(null, authN);
    }
  );
  twitterAuthz.name = 'twitterAuthz';

  passport.use(twitterAuthn);
  passport.use(twitterAuthz);


  function route(rest) {
    // Twitter AuthN
    // Handle the case that the user clicks "Sign In with Twitter" on our own app
    rest.get(
      '/authn/twitter'
    , passport.authenticate('twitterAuthn')
    );
    // Handle the oauth callback from twitter
    rest.get(
      '/authn/twitter/callback'
    , function (req, res, next) {
        passport.authenticate('twitterAuthn', function (err, user, info) {
          console.log('[auth] twitter auth n');
          opts.login(req, res, next, {
            error: err
          , user: user
          , info: info
          , successUrl: '/tw-close.html'
          , failureUrl: '/tw-error.html'
          , callback: function (user2, next2) {
              // If we don't have authorization, get it
              if (!user2.authorized) {
                res.redirect('/authz/twitter');
                return;
              }
              next2();
            }
          });
        })(req, res, next);
      }
    );

    // Twitter AuthZ
    // Handle the case that the user wants to use a direct message, but hasn't authorized yet
    rest.get(
      '/authz/twitter'
    , passport.authenticate('twitterAuthz')
    );
    rest.get(
      '/authz/twitter/callback'
    , function (req, res, next) {
        passport.authenticate('twitterAuthz', function (err, user, info) {
          console.log('[auth] twitter auth z');
          opts.login(req, res, next, {
            error: err
          , user: user
          , info: info
          , successUrl: '/tw-close.html'
          , failureUrl: '/tw-error.html'
          });
        })(req, res, next);
      }
    );
  }

  return route;
};
