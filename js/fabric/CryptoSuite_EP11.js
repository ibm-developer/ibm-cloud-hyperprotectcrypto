/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const api = require('fabric-client/lib/api'),
      async = require('async'),
      BN = require('bn.js'),
      deasync = require('deasync'),
      elliptic = require('elliptic'),
      EC = elliptic.ec,
      hashPrimitives = require('fabric-client/lib/hash'),
      EP11Key = require('./EP11Key'),
      ep11 = require('ep11'),
      {grpc, pb, util} = ep11,
      util2 = require('util'),
      utils = require('fabric-client/lib/utils'),
      logger = utils.getLogger('CryptoSuite_EP11'),
      KeyValueStore = require('./KeyValueStore');


class CryptoSuite_EP11 extends api.CryptoSuite {
  constructor(keySize, algorithm, opts={}) {
    if (!keySize) {
      throw new Error('keySize must be specified');
    }
    if (keySize !== 256 && keySize !== 384) {
      throw new Error('Illegal key size: ' + keySize + ' - this crypto suite only supports key sizes 256 or 384');
    }

    let hashAlgo;
    if (algorithm && typeof algorithm === 'string') {
      hashAlgo = algorithm;
    } else {
      hashAlgo = utils.getConfigSetting('crypto-hash-algo');
    }
    if (!hashAlgo || typeof hashAlgo !== 'string') {
      throw new Error(util2.format('Unsupported hash algorithm: %j', hashAlgo));
    }
    hashAlgo = hashAlgo.toUpperCase();
    const hashPair = `${hashAlgo}_${keySize}`;
    if (!api.CryptoAlgorithms[hashPair] || !hashPrimitives[hashPair]) {
      throw Error(util2.format('Unsupported hash algorithm and key size pair: %s', hashPair));
    }

    const {ep11Address, ep11Instance, ep11Token} = opts;

    if (!ep11Address) {
      throw new Error('Must provide an EP11 hostname and port');
    }

    if (!ep11Instance) {
      throw new Error('Must provide an EP11 instance ID');
    }

    if (!ep11Token) {
      throw new Error('Must provide an IAM token to be used with EP11');
    }

    super();

    logger.debug('Hash algorithm: %s, hash output size: %s', hashAlgo, keySize);

    this.keySize = keySize;

    this.ep11Address = ep11Address;
    this.ep11Instance = ep11Instance;
    this.ep11Token = ep11Token;

    this._ecdsaCurve = elliptic.curves[`p${keySize}`];
    this._ecdsa = new EC(this._ecdsaCurve);
    this._cryptoKeyStore = null;
    this._hashFunction = hashPrimitives[hashPair];

    this.credentials = grpc.credentials.combineChannelCredentials(
      grpc.credentials.createSsl(),
      grpc.credentials.createFromMetadataGenerator((opts, callback) => {
        const metadata = new grpc.Metadata();

        util.authMetadata(metadata, this.ep11Instance, this.ep11Token);

        return callback(null, metadata);
      }));

    this.client = new pb.Crypto(this.ep11Address, this.credentials);
  }

  setCryptoKeyStore(cryptoKeyStore) {
    this._cryptoKeyStore = KeyValueStore(cryptoKeyStore);
  }

  generateEphemeralKey() {
    let err, done = false, result;

    this.generateKey({
      ephemeral: true
    }).then(key => {
      result = key;
      done = true;
    }).catch(e => {
      err = e;
    });

    // Loop until an error occurs or key is returned
    deasync.loopWhile(() => err == undefined && !done);

    // Do not continue if an error occurred
    if (err) throw err;

    return result;
  }

  async generateKey(opts={}) {
    const curve = util[`OIDNamedCurveP${this.keySize}`];

    const publicEcTemplate = new util.AttributeMap(
      new util.Attribute(ep11.CKA_CLASS, ep11.CKO_PUBLIC_KEY),
      new util.Attribute(ep11.CKA_KEY_TYPE, ep11.CKK_EC),
      new util.Attribute(ep11.CKA_EC_PARAMS, curve),
      new util.Attribute(ep11.CKA_VERIFY, true)
    );

    const privateEcTemplate = new util.AttributeMap(
      new util.Attribute(ep11.CKA_CLASS, ep11.CKO_PRIVATE_KEY),
      new util.Attribute(ep11.CKA_KEY_TYPE, ep11.CKK_EC),
      new util.Attribute(ep11.CKA_SIGN, true)
    );

    const generated = await new Promise((resolve, reject) => {
      this.client.GenerateKeyPair({
        Mech: {
          Mechanism: ep11.CKM_EC_KEY_PAIR_GEN
        },
        PubKeyTemplate: publicEcTemplate,
        PrivKeyTemplate: privateEcTemplate
      }, (err, data) => {
        if (err) return reject(err);

        resolve(data);
      });
    });

    const key = new EP11Key(generated);

    if (opts.ephemeral === undefined || opts.ephemeral === false) {
      if (!this._cryptoKeyStore) {
        throw new Error('generateKey opts.ephemeral is false, which requires CryptoKeyStore to be set.');
      }

      let err, done = false;

      this._cryptoKeyStore._getKeyStore().then(store => {
        store.putKey(key).then(() => {
          done = true;
        }).catch(e => {
          e.message = `Failed to store key: ${e.message}`;
          err = e;
        });
      }).catch(e => {
        e.message = `Failed to get key store: ${e.message}`;
        err = e;
      });

      // Loop until an error occurs or key is stored
      deasync.loopWhile(() => err == undefined && !done);

      // Do not continue if an error occurred
      if (err) throw err;
    }

    return key;
  }

  deriveKey(key, opts) {
    throw new Error('Not implemented yet');
  }

  importKey(pem, opts) {
    throw new Error('Not implemented yet');
  }

  async getKey(ski) {
    if (!this._cryptoKeyStore) {
      throw new Error('getKey requires CryptoKeyStore to be set.');
    }

    const store = await this._cryptoKeyStore._getKeyStore();

    return await store.getKey(ski);
  }

  hash(msg, opts) {
    return this._hashFunction(msg);
  }

  sign(key, digest) {
    let [signature] = this._runSyncWaterfall([
      cb => {
        this.client.SignSingle({
          Mech: {
            Mechanism: ep11.CKM_ECDSA
          },
          PrivKey: key,
          Data: digest
        }, (err, data={}) => {
          cb(err, data.Signature);
        });
      }
    ]);

    if (!signature) {
      throw new Error('Failed to retrieve signature from grep11');
    }

    logger.debug('Signature: %s', signature.toString('hex'));

    return signature;
  }

  verify(key, signature, digest) {
    const pointHex = util.Asn1ECPublicKey.decode(key).point.data.toString('hex'),
          pubKey = this._ecdsa.keyFromPublic(pointHex, 'hex'),
          r = new BN(signature.slice(0, signature.length / 2).toString('hex'), 16),
          s = new BN(signature.slice(signature.length / 2).toString('hex'), 16);

    return pubKey.verify(digest, {r, s});
  }

  encrypt(key, plainText, opts) {
    throw new Error('Not implemented yet');
  }

  decrypt(key, cipherText, opts) {
    throw new Error('Not implemented yet');
  }


  // Function to make synchronous waterfall calls to grep11 and return the
  // result rather than triggering a callback
  _runSyncWaterfall(fns, timeout=30000) {
    let timer,
        cancel = false;

    const results = [];

    timer = setTimeout(() => {
      timer = null;

      // Cancel if timeout is reached
      cancel = true;
    }, timeout);

    // Wrap functions with cancel handler
    fns = fns.map(fn => {
      return (...args) => {
        let cb = args[args.length - 1];

        // Exit the async loop if canceled
        if (cancel) return cb(false);

        return fn(...args);
      };
    });

    async.waterfall(fns, (err, ..._results) => {
      clearTimeout(timer);
      timer = null;

      if (err) {
        throw err;
      }

      results.push(..._results);
    });

    deasync.loopWhile(() => timer);

    return results;
  }
}

module.exports = CryptoSuite_EP11;
