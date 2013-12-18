CWD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

OUTPUT_DIR=$CWD

NDK_ROOT="$HOME/android/android-ndk"

# Build zmq for Android
cd /tmp/
git clone https://github.com/zeromq/zeromq3-x.git
cd zeromq3-x/
./autogen.sh
./configure --enable-static --disable-shared --host=arm-linux-androideabi \
    --prefix=$OUTPUT_DIR LDFLAGS="-L$OUTPUT_DIR/lib" \
    CPPFLAGS="-fPIC -I$OUTPUT_DIR/include" LIBS="-lgcc"
make
make install
cd $CWD

# Install c++ bindings for zmq
cd /tmp/
git clone https://github.com/zeromq/cppzmq.git
cd cppzmq
cp zmq.hpp $OUTPUT_DIR/include
cd $CWD

# Build boost for Android
cd /tmp/
git clone https://github.com/pelya/Boost-for-Android.git
cd Boost-for-Android
./build-android.sh $NDK_ROOT
cp -a build/lib/. $OUTPUT_DIR/lib/
cp -a build/include/boost-1_53/. $OUTPUT_DIR/include/
cd $CWD

# Build udis86 for Android
cd /tmp/
git clone https://github.com/vmt/udis86.git
cd udis86
