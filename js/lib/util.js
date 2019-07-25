const asn1 = require('asn1.js'),
      Long = require('long'),
      {ConstantType} = require('./header_consts'),
      util = require('util');

const Asn1OID = asn1.define('Asn1OID', function () { this.objid(); });

const Asn1ECPublicKey = asn1.define('Asn1ECPublicKey', function () {
  this.seq().obj(
    this.key('key').seq().obj(
      this.key('type').objid(),
      this.key('curve').objid()
    ),
    this.key('point').bitstr()
  );
});


// ASN1-encoded objects
exports.OIDNamedCurveP224 = Asn1OID.encode([1, 3, 132, 0, 33]);
exports.OIDNamedCurveP256 = Asn1OID.encode([1, 2, 840, 10045, 3, 1, 7]);
exports.OIDNamedCurveP384 = Asn1OID.encode([1, 3, 132, 0, 34]);
exports.OIDNamedCurveP521 = Asn1OID.encode([1, 3, 132, 0, 35]);
exports.OIDECPublicKey = Asn1OID.encode([1, 2, 840, 10045, 2, 1]);
exports.OIDECPrivateKey = Asn1OID.encode([1, 2, 840, 113549, 1, 1, 1]);


class AttributeMap {
  constructor(...attributes) {
    attributes.forEach(attr => {
      if (!(attr instanceof Attribute)) {
        throw new Error('Attribute must be an Attribute');
      }

      this[attr.key] = attr.value;
    });
  }
}

exports.AttributeMap = AttributeMap;


class Attribute {
  constructor(key, value) {
    if (!(key instanceof ConstantType)) {
      throw new Error('Attribute key must be instance of ConstantType');
    }

    this.key = key;
    this.value = convertValue(value);
  }
}

exports.Attribute = Attribute;


function convertValue(value) {
  if (Long.isLong(value)) {
    return Buffer.from(value.toBytesBE());
  }

  switch (typeof value) {
    case 'boolean':
      return Buffer.from([value == true && 1 || 0]);

    case 'string':
      return Buffer.from(value);

    case 'number':
      return Buffer.from(Long.fromInt(value).toBytesBE());

    default:
      return value
  }
}

exports.getPubKeyBytesFromSPKI = function (spki) {
  return (Asn1ECPublicKey.decode(spki).point || {}).data;
};

exports.authMetadata = function (metadata, instance, token) {
  metadata.add('authorization', `Bearer ${token}`);
  metadata.add('bluemix-instance', instance);

  return metadata;
};
