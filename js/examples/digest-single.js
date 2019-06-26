const async = require('async'),
      ep11 = require('../'),
      {pb, util} = ep11;

const creds = new ep11.Credentials({
  apiKey: 'API KEY',
  iamUrl: 'https://iam.test.cloud.ibm.com',
  instance: 'INSTANCE ID',
  ssl: true
});

const client = new pb.Crypto('GREP11 URL:PORT', creds);

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
    client.Digest({
      State: state,
      Data: Buffer.from(digestData)
    }, (err, data={}) => {
      cb(err, data.Digest);
    });
  }
], (err, digest) => {
  if (err) throw err;

  console.log('DATA:', digestData);
  console.log('DIGEST:', digest.toString('hex'));
});
