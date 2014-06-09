'use strict';

/**
 * @ngdoc service
 * @name yololiumApp.StApi
 * @description
 * # StApi
 * Service in the yololiumApp.
 */
angular.module('yololiumApp')
  .service('StApi', function StApi() {
    // AngularJS will instantiate a singleton by calling "new" on this function
    return {
      apiPrefix: '/api'
    , oauthPrefix: '/oauth'
    , testProfiles: [
        { "role": "superuser"
        , "token": "xxxxxxxx-test-xxxx-xxxx-root-xxxxxx"
        }
      , { "role": "admin"
        , "token": "xxxxxxxx-test-xxxx-xxxx-admin-xxxxxx"
        }
      , { "role": "user"
        , "token": "xxxxxxxx-test-xxxx-xxxx-user-xxxxxxx"
        }
      , { "role": "guest"
        , "token": "xxxxxxxx-test-xxxx-xxxx-guest-xxxxxx"
        }
      ]
    };
  });
