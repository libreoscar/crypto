#!/bin/bash
PATH_CRYPTO=$GOPATH/src/github.com/libreoscar/crypto

function regen {
  protoc --plugin=grpc -I $GOPATH/src --go_out=plugins=grpc:$GOPATH/src $PATH_CRYPTO/"$1"
}

# Regenerate .pb.go files for the following .proto files.
regen crypto.proto
