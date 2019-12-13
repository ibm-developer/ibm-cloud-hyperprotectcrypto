#!/bin/bash

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

BASEDIR=$(dirname "$0")

IAM_API_KEY=<your_API_KEY>
IAM_ENDPOINT=https://iam.cloud.ibm.com
INSTANCE_ID=<your_HPCS_Instance_ID>
EP11_ADDRESS=<your_ep11_address:port>

echo "=== RUN   Example_getMechanismInfo"
node $BASEDIR/examples/mechanism-info.js

echo "=== RUN   Example_encryptAndDecrypt"
node $BASEDIR/examples/encrypt-and-decrypt.js

echo "=== RUN   Example_digest_single"
node $BASEDIR/examples/digest-single.js

echo "=== RUN   Example_digest_multiple"
node $BASEDIR/examples/digest-multiple.js

echo "=== RUN   Example_signAndVerifyUsingRSAKeyPair"
node $BASEDIR/examples/sign-and-verify-rsa.js

echo "=== RUN   Example_signAndVerifyUsingECDSAKeyPair"
node $BASEDIR/examples/sign-and-verify-ecdsa.js

echo "=== RUN   Example_wrapAndUnwrapKey"
node $BASEDIR/examples/wrap-and-unwrap-key.js

echo "=== RUN   Example_deriveKey"
node $BASEDIR/examples/derive-keys.js
