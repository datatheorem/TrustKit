#!/bin/bash

#################
# ATENÇÃO:
# - Precisa ter instalado no Xcode os devices e simuladores para
# iOS, tvOS e watchOS
#################

# Função para compilar para uma plataforma específica
compile_for_platform() {
    platform=$1
    target=$2
    output_folder=$3

    xcodebuild -project TrustKit.xcodeproj \
               -scheme "$target" \
               -destination "$platform" \
               -configuration Release \
               build \
               CONFIGURATION_BUILD_DIR="$output_folder" \
               ONLY_ACTIVE_ARCH=YES
}

# Criar diretórios para as saídas das compilações
rm -rf "build"
mkdir -p "build"

# Compilar para iOS devices
compile_for_platform "generic/platform=iOS" "TrustKit" "build/Release-iphoneos"

# Compilar para iOS Simulator
compile_for_platform "generic/platform=iOS Simulator" "TrustKit" "build/Release-iphonesimulator"

# Compilar para tvOS devices
compile_for_platform "generic/platform=tvOS" "TrustKit tvOS" "build/Release-appletvos"

# Compilar para tvOS Simulator
compile_for_platform "generic/platform=tvOS Simulator" "TrustKit tvOS" "build/Release-appletvsimulator"

# Compilar para watchOS devices
compile_for_platform "generic/platform=watchOS" "TrustKit watchOS" "build/Release-watchos"

# Compilar para watchOS Simulator
compile_for_platform "generic/platform=watchOS Simulator" "TrustKit watchOS" "build/Release-watchsimulator"

# Compilar para macOS
compile_for_platform "platform=macOS" "TrustKit OS X" "build/Release-macos"

# Compilar para macCatalyst
compile_for_platform "platform=macOS,variant=Mac Catalyst" "TrustKit" "build/Release-mac-catalyst"

# Criar xcframework
rm -rf "TrustKit.xcframework"
xcodebuild -create-xcframework \
           -framework "build/Release-iphoneos/TrustKit.framework" \
           -framework "build/Release-iphonesimulator/TrustKit.framework" \
           -framework "build/Release-appletvos/TrustKit.framework" \
           -framework "build/Release-appletvsimulator/TrustKit.framework" \
           -framework "build/Release-watchos/TrustKit.framework" \
           -framework "build/Release-watchsimulator/TrustKit.framework" \
           -framework "build/Release-macos/TrustKit.framework" \
           -framework "build/Release-mac-catalyst/TrustKit.framework" \
           -output "TrustKit.xcframework"

# Compactar
tar -czf "TrustKit.tar.gz" "TrustKit.xcframework"
