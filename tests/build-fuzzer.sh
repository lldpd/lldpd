#!/bin/bash -eu

build(){
   export CFLAGS="$1"
   export CXXFLAGS="$1"

   ./autogen.sh
   ./configure CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$CFLAGS" \
      --enable-fuzzer=yes --disable-shared --disable-hardening --enable-pie

   make -j$(nproc)
   mkdir -p tests/seed/fuzz-decode_Corpus
}

run(){
   cd tests
   ./fuzz-decode seed/fuzz-decode_Corpus seed/fuzz-decode_seed_corpus
}

help(){
   echo "use: ./$0 ASan | UBSan | MSan | Run"
}

case $1 in
   ASan) build "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link" ;;
   UBSan) build "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fsanitize=fuzzer-no-link" ;;
   MSan) build "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=memory -fsanitize-memory-track-origins -fsanitize=fuzzer-no-link" ;;
   run) run $2 ;;
   *) help ;;
esac
