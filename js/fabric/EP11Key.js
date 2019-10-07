/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const api = require('fabric-client/lib/api'),
      Hash = require('fabric-client/lib/hash'),
      {util} = require('ep11');


class EP11Key extends api.Key {
  constructor(keys) {
    super();

    this.pubKey = keys.PubKey;
    this.privKey = keys.PrivKey;
  }

  getSKI() {
    return Hash.SHA2_256(util.getPubKeyBytesFromSPKI(this.pubKey));
  }

  isSymmetric() {
    return false;
  }

  isPrivate() {
    return this.privKey !== undefined;
  }

  getPublicKey() {
    return new EP11Key({ PubKey: this.pubKey });
  }

  toBytes() {
    let key,
        _private = this.isPrivate();

    if (_private) {
      key = this.privKey;
    } else {
      key = this.pubKey;
    }

    return [
      `-----BEGIN ${_private && 'PRIVATE' || 'PUBLIC'} HSM KEY-----`,
      key.toString('base64').match(/(.{64}|.+)/g).join('\n'),
      `-----END ${_private && 'PRIVATE' || 'PUBLIC'} HSM KEY-----`,
      '' // blank line for extra newline
    ].join('\n');
  }
}

module.exports = EP11Key;
