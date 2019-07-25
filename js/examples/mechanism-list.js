const client = require('./client'),
      ep11 = require('../'),
      {pb, util} = ep11;

client.GetMechanismList({}, (err, data) => {
  if (err) throw err;

  console.log('MECHANISMS:', data.Mechs);
});
