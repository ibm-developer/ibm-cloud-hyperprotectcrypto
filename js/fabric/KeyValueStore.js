/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const api = require('fabric-client/lib/api.js'),
      EP11Key = require('./EP11Key.js'),
      utils = require('fabric-client/lib/utils.js');


const KeyValueStoreProxyMixin = (parent) => class KeyValueStoreProxy {
  constructor(opts) {
    parent = utils.newCryptoKeyStore(parent, opts);

    return parent._getKeyStore().then(store => {
      store.putKey = this._putKey;
      store.getKey = this._getKey;

      return store;
    });
  }

  _getKey(ski) {
    return this.getValue(_getKeyIndex(ski, true))
      .then(priv => {
        if (priv) {
          return new EP11Key({
            PrivKey: _bufferFromPEMString(priv)
          });
        }

        return this.getValue(_getKeyIndex(ski, false));
      }).then(pub => {
        if (pub instanceof EP11Key) return pub;

        if (pub) {
          return new EP11Key({
            PubKey: _bufferFromPEMString(pub)
          });
        }
      });
  }

  _putKey(key) {
    const idx = _getKeyIndex(key.getSKI(), key.isPrivate());
    const pem = key.toBytes();
    return this.setValue(idx, pem)
      .then(() => {
        return key;
      });
  }
};


module.exports = (parent) => {
  const superClass = parent._storeConfig.superClass;
  parent._storeConfig.superClass = KeyValueStoreProxyMixin(superClass);
  return parent;
};

exports.KeyValueStoreProxyMixin = KeyValueStoreProxyMixin;


function _getKeyIndex(ski, isPrivateKey) {
  if (isPrivateKey) {
    return ski + '_sk';
  } else {
    return ski + '_pk';
  }
}

function _bufferFromPEMString(pem) {
  return Buffer.from(pem.replace(/(-{5}(BEGIN|END)[^-]+KEY-{5}|\n)/g, ''), 'base64');
}
