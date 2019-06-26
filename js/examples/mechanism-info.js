const async = require('async'),
      ep11 = require('../'),
      {pb, util} = ep11,
      uuidv4 = require('uuid/v4');

const creds = new ep11.Credentials({
  apiKey: 'API KEY',
  iamUrl: 'https://iam.test.cloud.ibm.com',
  instance: 'INSTANCE ID',
  ssl: true
});

const client = new pb.Crypto('GREP11 URL:PORT', creds);

client.GetMechanismInfo({
  Mech: ep11.CKM_AES_KEY_GEN
}, (err, data) => {
  if (err) throw err;

  console.log('MECHANISM INFO:', data.MechInfo);
});
