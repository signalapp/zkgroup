#
#  Be sure to run `pod spec lint credential.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see http://docs.cocoapods.org/specification.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#

Pod::Spec.new do |s|
  s.name         = "ZKGroup"
  s.version      = "0.9.0"
  s.summary      = "Swift API for the Rust zkgroup crate."
  s.homepage     = "https://signal.org/"
  s.license      = { :type => "GPLv3", :file => "LICENSE" }
  s.authors      = { "Signal iOS" => "ios@signal.org" }
  s.source = { :git => "https://github.com/signalapp/zkgroup.git", :tag => "v#{s.version}" }

  s.swift_version    = '5'
  s.platform         = :ios, '10'

  s.source_files = 'ffi/swift/Sources/**/*.{m,swift}'
  s.preserve_paths = [
    'target/*/release/libzkgroup.a',
    'ffi/swift/Sources/libzkgroup',
  ]

  s.pod_target_xcconfig = {
      'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/ffi/swift/Sources/libzkgroup',
      # Duplicate this here to make sure the search path is passed on to Swift dependencies.
      'SWIFT_INCLUDE_PATHS' => '$(HEADER_SEARCH_PATHS)',

      # Make sure we link the static library, not a dynamic one.
      # Use an extra level of indirection because CocoaPods messes with OTHER_LDFLAGS too.
      'LIBZKGROUP_FFI_LIB_IF_NEEDED' => '$(PODS_TARGET_SRCROOT)/target/$(CARGO_BUILD_TARGET)/release/libzkgroup.a',
      'OTHER_LDFLAGS' => '$(LIBZKGROUP_FFI_LIB_IF_NEEDED)',

      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=arm64]' => 'aarch64-apple-ios-sim',
      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=*]' => 'x86_64-apple-ios',
      'CARGO_BUILD_TARGET[sdk=iphoneos*]' => 'aarch64-apple-ios',
      # Presently, there's no special SDK or arch for maccatalyst,
      # so we need to hackily use the "IS_MACCATALYST" build flag
      # to set the appropriate cargo target
      'CARGO_BUILD_TARGET_MAC_CATALYST_ARM_' => 'aarch64-apple-darwin',
      'CARGO_BUILD_TARGET_MAC_CATALYST_ARM_YES' => 'aarch64-apple-ios-macabi',
      'CARGO_BUILD_TARGET[sdk=macosx*][arch=arm64]' => '$(CARGO_BUILD_TARGET_MAC_CATALYST_ARM_$(IS_MACCATALYST))',
      'CARGO_BUILD_TARGET_MAC_CATALYST_X86_' => 'x86_64-apple-darwin',
      'CARGO_BUILD_TARGET_MAC_CATALYST_X86_YES' => 'x86_64-apple-ios-macabi',
      'CARGO_BUILD_TARGET[sdk=macosx*][arch=*]' => '$(CARGO_BUILD_TARGET_MAC_CATALYST_X86_$(IS_MACCATALYST))',

      'ARCHS[sdk=iphonesimulator*]' => 'x86_64 arm64',
      'ARCHS[sdk=iphoneos*]' => 'arm64',
  }

  s.user_target_xcconfig = {
      'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
  }

  s.script_phases = [
    { :name => 'Check libzkgroup',
      :execution_position => :before_compile,
      :script => %q(
        test -e "${LIBZKGROUP_FFI_LIB_IF_NEEDED}" && exit 0
        if test -e "${PODS_TARGET_SRCROOT}/ffi/swift/build_ffi.sh"; then
          echo 'error: libzkgroup.a not built; run the following to build it:' >&2
          echo "CARGO_BUILD_TARGET=${CARGO_BUILD_TARGET} \"${PODS_TARGET_SRCROOT}/ffi/swift/build_ffi.sh\" --release" >&2
        else
          echo 'error: libzkgroup.a not built; try re-running `pod install`' >&2
        fi
        false
      ),
    }
  ]

  s.prepare_command = %q(
    set -euo pipefail
    CARGO_BUILD_TARGET=aarch64-apple-ios ffi/swift/build_ffi.sh --release
    CARGO_BUILD_TARGET=x86_64-apple-ios ffi/swift/build_ffi.sh --release
    CARGO_BUILD_TARGET=aarch64-apple-ios-sim ffi/swift/build_ffi.sh --release
    CARGO_BUILD_TARGET=x86_64-apple-ios-macabi ffi/swift/build_ffi.sh --release --build-std
    CARGO_BUILD_TARGET=aarch64-apple-ios-macabi ffi/swift/build_ffi.sh --release --build-std
  )

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'ffi/swift/Tests/**/*.{m,swift}'
  end
end
