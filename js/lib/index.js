/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const pb = require('./pb'),
      path = require('path');

Object.assign(module.exports, {},
  require('./header_consts.js'),
  {
    grpc: require('grpc'),
    pb: pb.loadProto(path.join(__dirname, '..', '..', 'protos', 'server.proto')),
    util: require('./util')
  }
);
