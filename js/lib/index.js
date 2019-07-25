const pb = require('./pb'),
      path = require('path');

Object.assign(module.exports, {},
  require('./header_consts.js'),
  {
    pb: pb.loadProto(path.join(__dirname, '..', '..', 'protos', 'server.proto')),
    util: require('./util')
  }
);
