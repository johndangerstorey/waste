'use strict';

console.log('\n\n\nWelcome to WASTE!');

//var config = require('./device.json');
var securePort = process.argv[2] || 4443 || 443;
var insecurePort = process.argv[3] || 4080 || 80;
var redirects = require('./redirects.json');
var path = require('path');

    // force SSL upgrade server
var certsPath = path.join(__dirname, 'certs');
// require('ssl-root-cas').inject();
var vhostsdir = path.join(__dirname, 'vhosts');

require('./lib/insecure-server').create(securePort, insecurePort, redirects).then(function (insecureServer) {
  insecureServer.on('error', function (err) {
    if (/EADDRINUSE/.test(err.toString())) {
      console.error('\n' + err.toString());
      console.error('::: The insecure server is probably running on port ' + insecurePort + ' in another tab.');
      process.exit();
      return;
    }
    throw err;
  });
});
require('./lib/vhost-sni-server.js').create(securePort, certsPath, vhostsdir).then(function (secureServer) {
  secureServer.on('error', function (err) {
    if (/EADDRINUSE/.test(err.toString())) {
      console.error('\n' + err.toString());
      console.error('::: The secure server is probably running on port ' + securePort + ' in another tab.');
      process.exit();
      return;
    }
    throw err;
  });
})
  //.then(phoneHome)
  ;
