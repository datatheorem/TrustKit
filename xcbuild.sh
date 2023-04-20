#!/bin/sh
set -e
set -o xtrace

# WORKSPACE=""
PROJECT="TrustKit.xcodeproj"
SCHEME="TrustKit"
FRAMEWORK_NAME="TrustKit"

BUILD_DIR=${PWD}/"_build"
IOS_ARCHIVE_PATH="${BUILD_DIR}/iOSDevice.xcarchive"
IOS_SIM_ARCHIVE_PATH="${BUILD_DIR}/iOSSimulator.xcarchive"
LIB=${PWD}/"lib"
PROJECT_DIR=${PWD}

rm -rf ${BUILD_DIR}
rm -rf "${LIB}/${FRAMEWORK_NAME}.xcframework"

build_sim() {
    cd $PROJECT_DIR

    xcodebuild archive \
        -scheme ${SCHEME} \
        -project ${PROJECT} \
        -destination="iOS Simulator" \
        -archivePath "${IOS_SIM_ARCHIVE_PATH}" \
        -sdk iphonesimulator \
        SKIP_INSTALL=NO \
        BUILD_LIBRARIES_FOR_DISTRIBUTION=YES \
        SWIFT_SERIALIZE_DEBUGGING_OPTIONS=NO
    
    cd ${PWD}
}

build_device() {
    cd $PROJECT_DIR

    xcodebuild archive \
        -scheme ${SCHEME} \
        -project ${PROJECT} \
        -destination="iOS" \
        -archivePath "${IOS_ARCHIVE_PATH}" \
        -sdk iphoneos \
        SKIP_INSTALL=NO \
        BUILD_LIBRARIES_FOR_DISTRIBUTION=YES \
        SWIFT_SERIALIZE_DEBUGGING_OPTIONS=NO

    cd ${PWD}
}

prep() {
    cd ${PROJECT_DIR}
    # rm -rf Pods
    # pod install
    cd ..
}

make_xcframework() {
    xcodebuild -create-xcframework \
        -framework ${IOS_SIM_ARCHIVE_PATH}/Products/Library/Frameworks/${FRAMEWORK_NAME}.framework \
        -debug-symbols ${IOS_SIM_ARCHIVE_PATH}/dSYMs/${FRAMEWORK_NAME}.framework.dSYM \
        -framework ${IOS_ARCHIVE_PATH}/Products/Library/Frameworks/${FRAMEWORK_NAME}.framework \
        -debug-symbols ${IOS_ARCHIVE_PATH}/dSYMs/${FRAMEWORK_NAME}.framework.dSYM \
        -output ${LIB}/${FRAMEWORK_NAME}.xcframework
}

# prep
build_sim
build_device
make_xcframework

# zip -r ${FRAMEWORK_NAME}.xcframework.zip ${FRAMEWORK_NAME}.xcframework
rm -rf ${BUILD_DIR}
# rm -rf ${FRAMEWORK_NAME}.xcframework
