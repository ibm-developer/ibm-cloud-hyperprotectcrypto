const async = require('async'),
      client = require('./client'),
      ep11 = require('../'),
      {pb, util} = ep11,
      uuidv4 = require('uuid/v4');

const message = 'Hello, this is a very long and creative message without any imagination';

async.waterfall([
  // Generate key
  cb => {
    let keyLen = 128;

    let keyTemplate = new util.AttributeMap(
      new util.Attribute(ep11.CKA_VALUE_LEN, keyLen / 8),
      new util.Attribute(ep11.CKA_WRAP, false),
      new util.Attribute(ep11.CKA_UNWRAP, false),
      new util.Attribute(ep11.CKA_ENCRYPT, true),
      new util.Attribute(ep11.CKA_DECRYPT, true),
      new util.Attribute(ep11.CKA_EXTRACTABLE, false),
      new util.Attribute(ep11.CKA_TOKEN, true)
    );

    client.GenerateKey({
      Mech: { Mechanism: ep11.CKM_AES_KEY_GEN },
      Template: keyTemplate,
      KeyId: uuidv4()
    }, (err, data={}) => {
      cb(err, data.Key, data.CheckSum);
    });
  },

  // Generate IV
  (key, checksum, cb) => {
    client.GenerateRandom({
      Len: ep11.AES_BLOCK_SIZE
    }, (err, data={}) => {
      cb(err, key, checksum, data.Rnd);
    });
  }
], (err, key, checksum, iv) => {
  if (err) throw err;

  async.waterfall([
    // Encrypt plaintext
    cb => {
      async.waterfall([
        cb => {
          client.EncryptInit({
            Mech: {
              Mechanism: ep11.CKM_AES_CBC_PAD,
              Parameter: iv
            },
            Key: key
          }, (err, data={}) => {
            cb(err, data.State);
          });
        },

        (state, cb) => {
          client.EncryptUpdate({
            State: state,
            Plain: Buffer.from(message.substr(0, 20))
          }, (err, data={}) => {
            cb(err, data.State, data.Ciphered);
          });
        },

        (state, ciphertext, cb) => {
          client.EncryptUpdate({
            State: state,
            Plain: Buffer.from(message.substr(20))
          }, (err, data={}) => {
            cb(err, data.State, Buffer.concat([ciphertext, data.Ciphered]));
          });
        },

        (state, ciphertext, cb) => {
          client.EncryptFinal({
            State: state
          }, (err, data={}) => {
            cb(err, Buffer.concat([ciphertext, data.Ciphered]));
          });
        }
      ], (err, ciphertext) => {
        cb(err, ciphertext);
      });
    },

    // Decrypt ciphertext
    (ciphertext, cb) => {
      async.waterfall([
        cb => {
          client.DecryptInit({
            Mech: {
              Mechanism: ep11.CKM_AES_CBC_PAD,
              Parameter: iv
            },
            Key: key
          }, (err, data={}) => {
            cb(err, data.State);
          });
        },

        (state, cb) => {
          client.DecryptUpdate({
            State: state,
            Ciphered: ciphertext.slice(0, 16)
          }, (err, data={}) => {
            cb(err, data.State, data.Plain);
          });
        },

        (state, plaintext, cb) => {
          client.DecryptUpdate({
            State: state,
            Ciphered: ciphertext.slice(16)
          }, (err, data={}) => {
            cb(err, data.State, Buffer.concat([plaintext, data.Plain]));
          });
        },

        (state, plaintext, cb) => {
          client.DecryptFinal({
            State: state
          }, (err, data={}) => {
            cb(err, Buffer.concat([plaintext, data.Plain]));
          });
        }
      ], (err, plaintext) => {
        cb(err, ciphertext, plaintext);
      });
    }
  ], (err, ciphertext, plaintext) => {
    if (err) throw err;

    console.log('MESSAGE:', message);
    console.log('CIPHERTEXT:', ciphertext.toString('hex'));
    console.log('PLAINTEXT:', plaintext.toString());

    if (plaintext.toString() !== message) {
      throw new Error('Plaintext does not match original message');
    }
  });
});
