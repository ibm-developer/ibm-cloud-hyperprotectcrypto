const ep11 = require('../'),
      {Credentials} = require('./credentials'),
      {pb} = ep11;


let apiKey = 'API KEY',
    iamEndpoint = 'https://iam.test.cloud.ibm.com',
    instanceId = 'INSTANCE ID',
    ep11Address = 'GREP11 URL:PORT';


const creds = new Credentials({
  apiKey: process.env.IAM_API_KEY || apiKey,
  iamUrl: process.env.IAM_ENDPOINT || iamEndpoint,
  instance: process.env.INSTANCE_ID || instanceId,
  ssl: true
});

const client = new pb.Crypto(process.env.EP11_ADDRESS || ep11Address, creds);

module.exports = client;
