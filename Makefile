# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

build-protos:
	@echo "=== Building the proto bindings ==="
	protoc  protos/*.proto \
	        -Iprotos \
	        -Ivendor/github.com/gogo/protobuf/gogoproto \
	        -Ivendor/github.com/gogo/googleapis \
	  --gogofast_out=plugins=grpc,\
Mgoogle/protobuf/descriptor.proto=github.com/gogo/protobuf/protoc-gen-gogo/descriptor,\
Mgoogle/api/annotations.proto=github.com/gogo/googleapis/google/api:./golang/grpc
	gofmt -w -s golang/ep11