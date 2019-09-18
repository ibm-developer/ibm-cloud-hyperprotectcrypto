/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const grpc = require('grpc'),
      loader = require('@grpc/proto-loader');

exports.loadProto = function (path) {
  let def = loader.loadSync(path, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  });

  return grpc.loadPackageDefinition(def).grep11;
};
