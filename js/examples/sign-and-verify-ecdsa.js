const async = require('async'),
      client = require('./client'),
      crypto = require('crypto'),
      ep11 = require('../'),
      {pb, util} = ep11;

const dataToSign = crypto.createHash('sha256')
  .update('This data needs to be signed')
  .digest('hex');

const publicKeyTemplate = new util.AttributeMap(
  new util.Attribute(ep11.CKA_EC_PARAMS, util.OIDNamedCurveP256),
  new util.Attribute(ep11.CKA_VERIFY, true),
  new util.Attribute(ep11.CKA_EXTRACTABLE, false),
);

const privateKeyTemplate = new util.AttributeMap(
  new util.Attribute(ep11.CKA_SIGN, true),
  new util.Attribute(ep11.CKA_EXTRACTABLE, false),
);

client.GenerateKeyPair({
  Mech: {
    Mechanism: ep11.CKM_EC_KEY_PAIR_GEN
  },
  PubKeyTemplate: publicKeyTemplate,
  PrivKeyTemplate: privateKeyTemplate
}, (err, keys) => {
  if (err) throw err;

  async.waterfall([
    cb => {
      client.SignInit({
        Mech: {
          Mechanism: ep11.CKM_ECDSA
        },
        PrivKey: keys.PrivKey
      }, (err, data={}) => {
        cb(err, data.State);
      });
    },

    (state, cb) => {
      client.Sign({
        State: state,
        Data: dataToSign
      }, (err, data={}) => {
        cb(err, data.Signature);
      });
    },

    (signature, cb) => {
      client.VerifyInit({
        Mech: {
          Mechanism: ep11.CKM_ECDSA
        },
        PubKey: keys.PubKey
      }, (err, data={}) => {
        cb(err, signature, data.State);
      });
    },

    (signature, state, cb) => {
      client.Verify({
        State: state,
        Data: dataToSign,
        Signature: signature
      }, (err, data={}) => {
        cb(err, signature);
      });
    }
  ], (err, signature) => {
    if (err) throw err;

    console.log('DATA:', dataToSign);
    console.log('VERIFIED SIGNATURE:', signature.toString('hex'));
  });
});
