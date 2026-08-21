Pod::Spec.new do |spec|
  spec.name = 'SecureKeypadReactNative'
  spec.version = '0.1.0'
  spec.summary = 'Secure Native keypad React Native bridge'
  spec.description = 'A native-only keypad bridge that exports masked state and public result codes.'
  spec.homepage = 'https://github.com/uulab/secure-keyboard'
  spec.license = { :type => 'MIT' }
  spec.author = { 'UULab' => 'security@uulab.dev' }
  spec.source = { :git => 'https://github.com/uulab/secure-keyboard.git', :tag => spec.version.to_s }
  spec.platforms = { :ios => '15.0' }
  spec.swift_version = '5.9'
  spec.requires_arc = true
  spec.source_files = 'ios/**/*.{h,m,swift}'
  spec.preserve_paths = 'ios/SecureKeypadFFI/**/*'
  spec.public_header_files = 'ios/SecureKeypadFFI/secure_keypad.h'
  spec.dependency 'React-Core'
  spec.frameworks = 'UIKit'
  spec.pod_target_xcconfig = {
    'SWIFT_INCLUDE_PATHS' => '$(PODS_TARGET_SRCROOT)/ios/SecureKeypadFFI',
    'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/ios/SecureKeypadFFI'
  }

  ffi_library = ENV['SECURE_KEYPAD_FFI_LIB']
  unless ffi_library && File.file?(ffi_library)
    raise 'SECURE_KEYPAD_FFI_LIB must point to the matching secure_ffi static library before pod install'
  end
  spec.vendored_libraries = ffi_library
end
