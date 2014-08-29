'use strict';

var UUID = require('node-uuid')
  , crypto = require('crypto')
  ;

module.exports.create = function (DB) {
  // TODO periodically remove expired codes
  // TODO ensure checkId uniqueness (one email address can't have several concurrent authcode attempts)
  // TODO ban by host identifier (ip address)
  // TODO change key length based on duration

  function Codes() {
  }

  Codes.create = function (opts) {
    var now = Date.now()
      , duration = opts.duration || 2 * 60 * 1000
      ;

    function lookupId(id) {
      return DB.AuthCodes.forge({ check_id: id }).fetch().then(function ($code) {
        if (!$code) {
          return null;
        }

        if (now > $code.get('expiresAt').valueOf()) {
          return $code.destroy().then(function () {
            return null;
          });
        }

        return $code;
      });
    }

    function doStuff($code) {
      if ($code) {
        throw { message: "there is an outstanding reset. please check your email and or sms" };
      }

      opts = opts || {};
      var uuid = UUID.v4()
        , num = parseInt(crypto.randomBytes(8).toString('hex'), 16)
        , code = (num / 10000000).toFixed(8).replace(/.*\.(\d{3})(\d{3}).*/, '$1-$2')
          //Math.random().toString().substr(2).replace(/(\d{3})(\d{3}).*/, "$1-$2")
        ;

      $code = DB.AuthCodes.forge();

      $code.set('uuid', uuid);
      // TODO check against hash of code instead of code itself?
      $code.set('code', code);
      if (opts.checkId) {
        $code.set('checkId', opts.checkId);
      }
      $code.set('expiresAt', new Date(now + duration));

      return $code.save({}, { method: 'insert' }).then(function () {
        return $code;
      });
    }

    if (opts.checkId) {
      return lookupId(opts.checkId).then(doStuff);
    }

    return doStuff();
  };

  Codes.validate = function (uuid, code, opts) {
    opts = opts || {};
    return DB.AuthCodes.forge({ uuid: uuid }).fetch().then(function ($code) {
      function fail(err, opts) {
        opts = opts || {};

        if (!$code) {
          // TODO log IP address
          throw err;
        }

        if (opts.destroy) {
          return $code.destroy().then(function () {
            throw err;
          });
        }

        attempts.unshift(new Date());
        $code.set('attempts', attempts);
        return $code.save().then(function () {
          throw err;
        }, function (err) {
          console.error('[ERROR] authcodes fail()');
          console.error(err);
        });
      }

      if (!$code) {
        return fail({ message: "the token has expired or does not exist" });
      }

      var now = Date.now()
        , attempts = $code.get('attempts') || []
        , expiresAt = $code.get('expiresAt')
        , lastAttempt = attempts[0]
        , msPerAttempt = 1 * 1000
        , maxAttempts = 3
        ;

      if (now > expiresAt.valueOf()) {
        return fail({ message: "this token has expired" }, { destroy: true });
      }

      if (now - lastAttempt < msPerAttempt) {
        return fail({ message: "you must wait 1 second between auth code attempts" });
      }

      if (attempts.length >= maxAttempts - 1) {
        // don't destroy the token until it has expired
        return fail({ message: "you have tried to authorize this code too many times" });
      }

      if (code !== $code.get('code')) {
        return fail({ message: "you have entered the code incorrectly. "
          + (maxAttempts - (attempts.length + 1) + " attempts remaining")
        }/*, { destroy: 0 === (maxAttempts - (attempts.length + 1)) }*/);
      }

      if (opts.checkId !== $code.get('checkId')) {
        return fail({ message: "you have tried to authorize this code against the wrong account" });
      }

      return $code.destroy().then(function () {
        return true;
      });
    });
  };

  return Codes;
};