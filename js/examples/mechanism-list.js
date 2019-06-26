const ep11 = require('../'),
      {pb, util} = ep11;

const creds = new ep11.Credentials({
  apiKey: 'API KEY',
  iamUrl: 'https://iam.test.cloud.ibm.com',
  instance: 'INSTANCE ID',
  ssl: true
});

const client = new pb.Crypto('GREP11 URL:PORT', creds);

client.GetMechanismList({}, (err, data) => {
  if (err) throw err;

  console.log('MECHANISMS:', data.Mechs);
});
