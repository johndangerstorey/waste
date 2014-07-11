'use strict';

module.exports.create = function () {
  // These are just fallthrough routes
  // The real logic is handled in the sessionlogic stuff
  // (and this all should probably move there)
  function route(rest) {

    function getGuest(method, type) {
      return {
        as: method
      , type: type
      , logins: []
      , accounts: []
      , account: { role: 'guest' }
      };
    }

    function getPublic(reqUser) {
      if (!reqUser) {
        return null;
      }

      return {
        mostRecentLoginId: reqUser.login.id
      , selectedAccountId: reqUser.account && reqUser.account.id
      , logins: reqUser.logins.map(function (authN) {
          authN = JSON.parse(JSON.stringify(authN));
          authN.profile.uid = authN.profile.id;
          authN.profile.type = authN.type;
          authN.profile.pkey = authN.id;
          authN.profile.typedUid = authN.id;
          authN.profile.id = authN.id;
          return authN.profile;
        })
      , accounts: reqUser.accounts
      };
    }

    rest.get('/session', function (req, res) {
      /*
        { login: {}
        , logins: []
        , account: {}
        , accounts: []
        }
      */
      res.send(getPublic(req.user) || getGuest('get'));
    });
    // this is the fallthrough from the POST '/api' catchall
    rest.post('/session', function (req, res) {
      res.send(getPublic(req.user) || getGuest('post'));
    });
    // TODO have separate error / guest and valid user fallthrough
    rest.post('/session/:type', function (req, res) {
      res.send(getPublic(req.user) || getGuest('post', req.params.type) );
    });
    rest.delete('/session', function (req, res) {
      req.logout();
      res.send(getGuest('delete'));
    });
  }

  return {
    route: route
  };
};