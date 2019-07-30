const async = require('async'),
      client = require('./client'),
      ep11 = require('../'),
      {pb, util} = ep11;

const message = 'Hello World!';

const publicEcTemplate = new util.AttributeMap(
  new util.Attribute(ep11.CKA_EC_PARAMS, util.OIDNamedCurveP256),
  new util.Attribute(ep11.CKA_EXTRACTABLE, false)
);

const privateEcTemplate = new util.AttributeMap(
  new util.Attribute(ep11.CKA_DERIVE, true),
  new util.Attribute(ep11.CKA_EXTRACTABLE, false)
);

const generateKeyPairRequest = {
  Mech: {
    Mechanism: ep11.CKM_EC_KEY_PAIR_GEN
  },
  PubKeyTemplate: publicEcTemplate,
  PrivKeyTemplate: privateEcTemplate
};

// Generate 2 sets of key pairs
async.timesSeries(2, (i, cb) => {
  client.GenerateKeyPair(generateKeyPairRequest, cb);
}, (err, results) => {
  if (err) throw err;

  // Grab keys from results; one set for Alice and one set for Bob
  const [alice, bob] = results;

  const deriveKeyTemplate = new util.AttributeMap(
    new util.Attribute(ep11.CKA_CLASS, ep11.CKO_SECRET_KEY),
    new util.Attribute(ep11.CKA_KEY_TYPE, ep11.CKK_AES),
    new util.Attribute(ep11.CKA_VALUE_LEN, 128/8),
    new util.Attribute(ep11.CKA_ENCRYPT, true),
    new util.Attribute(ep11.CKA_DECRYPT, true),
  );

  const derived = [];

  async.eachSeries([
    { PubKey: bob.PubKey, PrivKey: alice.PrivKey },
    { PubKey: alice.PubKey, PrivKey: bob.PrivKey }
  ], (data, cb) => {
    const combinedCoordinates = util.getPubKeyBytesFromSPKI(data.PubKey);

    client.DeriveKey({
      Mech: {
        Mechanism: ep11.CKM_ECDH1_DERIVE,
        Parameter: combinedCoordinates
      },
      Template: deriveKeyTemplate,
      BaseKey: data.PrivKey
    }, (err, data={}) => {
      if (!err) {
        derived.push(data);
      }

      cb(err);
    });
  }, (err) => {
    if (err) throw err;

    // Grab new keys from results
    const [aliceDerived, bobDerived] = derived;

    // Encrypt and decrypt message with derived keys
    async.waterfall([
      cb => {
        client.GenerateRandom({
          Len: ep11.AES_BLOCK_SIZE
        }, (err, data={}) => {
          cb(err, data.Rnd);
        });
      },

      (iv, cb) => {
        client.EncryptSingle({
          Mech: {
            Mechanism: ep11.CKM_AES_CBC_PAD,
            Parameter: iv
          },
          Key: aliceDerived.NewKey,
          Plain: Buffer.from(message)
        }, (err, data={}) => {
          cb(err, iv, data.Ciphered);
        });
      },

      (iv, ciphertext, cb) => {
        client.DecryptSingle({
          Mech: {
            Mechanism: ep11.CKM_AES_CBC_PAD,
            Parameter: iv
          },
          Key: bobDerived.NewKey,
          Ciphered: ciphertext
        }, (err, data={}) => {
          cb(err, ciphertext, data.Plain);
        });
      }
    ], (err, ciphertext, plaintext) => {
      console.log('MESSAGE:', message);
      console.log('CIPHERTEXT:', ciphertext.toString('hex'));
      console.log('PLAINTEXT:', plaintext.toString());

      if (plaintext.toString() !== message) {
        throw new Error('Plaintext does not match original message');
      }
    });
  });
});

