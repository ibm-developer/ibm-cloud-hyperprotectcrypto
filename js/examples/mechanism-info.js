const async = require('async'),
      client = require('./client'),
      ep11 = require('../'),
      {pb, util} = ep11,
      uuidv4 = require('uuid/v4');

client.GetMechanismInfo({
  Mech: ep11.CKM_AES_KEY_GEN
}, (err, data) => {
  if (err) throw err;

  console.log('MECHANISM INFO:', data.MechInfo);
});
