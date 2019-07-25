const grpc = require('grpc'),
      request = require('request'),
      {util} = require('../');

class Credentials {
  constructor(options={}) {
    this.options = options;

    let credentials = [];

    if (this.options.ssl) {
      credentials.push(grpc.credentials.createSsl());
    }

    credentials.push(grpc.credentials.createFromMetadataGenerator((...args) => {
      return this.generate(...args);
    }));

    return grpc.credentials.combineChannelCredentials(...credentials);
  }

  generate(options, callback) {
    this.getToken((err, data) => {
      if (err) {
        return callback({
          code: err,
          message: data
        });
      }

      let metadata = new grpc.Metadata();

      // Populate metadata object with headers required for authorization
      util.authMetadata(metadata, this.options.instance, data);

      return callback(null, metadata);
    });
  }

  getToken(callback) {
    if (this.token && this.token_expiration > Date.now()) {
      return callback(null, this.token);
    }

    let options = {
      method: 'POST',
      url: `${this.options.iamUrl || 'https://iam.cloud.ibm.com'}/identity/token`,
      json: true,
      qs: {
        grant_type: 'urn:ibm:params:oauth:grant-type:apikey',
        apikey: this.options.apiKey
      }
    };

    request(options, (err, res, data) => {
      if (err) return callback(err, data);

      if (data.errorCode || data.errorMessage) {
        return callback(data.errorCode, data.errorMessage);
      }

      this.token = data.access_token;
      this.token_expiration = new Date(data.expiration * 1000);

      callback(null, this.token);
    });
  }
}

exports.Credentials = Credentials;
