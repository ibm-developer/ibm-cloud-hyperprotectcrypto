const async = require('async'),
      client = require('./client'),
      crypto = require('crypto'),
      ep11 = require('../'),
      {pb, util} = ep11,
      uuidv4 = require('uuid/v4');

const aesKeyTemplate = new util.AttributeMap(
  new util.Attribute(ep11.CKA_VALUE_LEN, 128/8),
  new util.Attribute(ep11.CKA_ENCRYPT, true),
  new util.Attribute(ep11.CKA_DECRYPT, true),
  new util.Attribute(ep11.CKA_EXTRACTABLE, true), // must be true to be wrapped
);

const publicExponent = 0x11;

const publicKeyTemplate = new util.AttributeMap(
  new util.Attribute(ep11.CKA_ENCRYPT, true),
  new util.Attribute(ep11.CKA_WRAP, true),
  new util.Attribute(ep11.CKA_MODULUS_BITS, 2048),
  new util.Attribute(ep11.CKA_PUBLIC_EXPONENT, publicExponent),
  new util.Attribute(ep11.CKA_EXTRACTABLE, false)
);

const privateKeyTemplate = new util.AttributeMap(
  new util.Attribute(ep11.CKA_PRIVATE, true),
  new util.Attribute(ep11.CKA_SENSITIVE, true),
  new util.Attribute(ep11.CKA_DECRYPT, true),
  new util.Attribute(ep11.CKA_UNWRAP, true),
  new util.Attribute(ep11.CKA_EXTRACTABLE, false)
);

const aesUnwrapKeyTemplate = new util.AttributeMap(
  new util.Attribute(ep11.CKA_CLASS, ep11.CKO_SECRET_KEY),
  new util.Attribute(ep11.CKA_KEY_TYPE, ep11.CKK_AES),
  new util.Attribute(ep11.CKA_VALUE_LEN, 128/8),
  new util.Attribute(ep11.CKA_ENCRYPT, true),
  new util.Attribute(ep11.CKA_DECRYPT, true),
  new util.Attribute(ep11.CKA_EXTRACTABLE, true)
);

async.waterfall([
  cb => {
    client.GenerateKey({
      Mech: {
        Mechanism: ep11.CKM_AES_KEY_GEN
      },
      Template: aesKeyTemplate,
      KeyId: uuidv4()
    }, cb);
  },

  (aes, cb) => {
    client.GenerateKeyPair({
      Mech: {
        Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN
      },
      PubKeyTemplate: publicKeyTemplate,
      PrivKeyTemplate: privateKeyTemplate,
      PubKeyId: uuidv4(),
      PrivKeyId: uuidv4()
    }, (err, data={}) => {
      cb(err, aes, data);
    });
  }
], (err, aes, rsa) => {
  if (err) throw err;

  async.waterfall([
    cb => {
      client.WrapKey({
        Mech: {
          Mechanism: ep11.CKM_RSA_PKCS
        },
        KeK: rsa.PubKey,
        Key: aes.Key
      }, (err, data={}) => {
        cb(err, data.Wrapped);
      });
    },

    (wrapped, cb) => {
      client.UnwrapKey({
        Mech: {
          Mechanism: ep11.CKM_RSA_PKCS
        },
        KeK: rsa.PrivKey,
        Wrapped: wrapped,
        Template: aesUnwrapKeyTemplate
      }, (err, data={}) => {
        cb(err, wrapped, data.Unwrapped, data.CheckSum);
      });
    }
  ], (err, wrapped, unwrapped, checksum) => {
    console.log('AES KEY:', aes.Key.toString('hex'));
    console.log('WRAPPED:', wrapped.toString('hex'));
    console.log('CHECKSUM:', checksum.toString('hex'));
    console.log('UNWRAPPED KEY:', unwrapped.toString('hex'));

    if (Buffer.compare(aes.CheckSum, checksum.slice(0, aes.CheckSum.length))) {
      throw new Error('Unwrapped key checksum does not match AES key checksum');
    }
  });
});
