#!/bin/bash -eu

build(){
   export CFLAGS="$1"
   export CXXFLAGS="$1"

   ./autogen.sh
   ./configure CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$CFLAGS" \
      --enable-fuzzer=yes --disable-shared --disable-hardening --enable-pie

   make -j$(nproc)

   pushd tests/seed/
   mkdir fuzz-decode_Corpus
   popd
}

run(){
   DIR=./seed
   pushd tests
   ./fuzz-decode $DIR/fuzz-decode_Corpus $DIR/fuzz-decode_seed_corpus
   popd
}

help(){
   echo "use: ./$0 ASan | UBSan | MSan | Run"
}

if [ -z "$1" ]
then
   help
elif [ $1 == "ASan" ]
then
   build "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
elif [ "$1" == "UBSan" ]
then
   build "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fsanitize=fuzzer-no-link"
elif [ "$1" == "MSan" ]
then
   build "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=memory -fsanitize-memory-track-origins -fsanitize=fuzzer-no-link"
elif [ "$1" == "Run" ]
then
   run $2
else
  help
fi
