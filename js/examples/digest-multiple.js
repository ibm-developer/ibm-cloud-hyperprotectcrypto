const async = require('async'),
      client = require('./client'),
      ep11 = require('../'),
      {pb, util} = ep11;

const digestData = 'This is the data longer than 64 bytes This is the data longer than 64 bytes';

async.waterfall([
  cb => {
    client.DigestInit({
      Mech: {
        Mechanism: ep11.CKM_SHA256
      }
    }, (err, data={}) => {
      cb(err, data.State);
    });
  },

  (state, cb) => {
    client.DigestUpdate({
      State: state,
      Data: Buffer.from(digestData.substr(0, 64))
    }, (err, data={}) => {
      cb(err, data.State);
    });
  },

  (state, cb) => {
    client.DigestUpdate({
      State: state,
      Data: Buffer.from(digestData.substr(64))
    }, (err, data={}) => {
      cb(err, data.State);
    });
  },

  (state, cb) => {
    client.DigestFinal({
      State: state
    }, (err, data={}) => {
      cb(err, data.Digest);
    });
  }
], (err, digest) => {
  if (err) throw err;

  console.log('DATA:', digestData);
  console.log('DIGEST:', digest.toString('hex'));
});
