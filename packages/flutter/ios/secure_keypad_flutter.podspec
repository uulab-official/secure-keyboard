Pod::Spec.new do |spec|
  spec.name = 'secure_keypad_flutter'
  spec.version = '0.1.0'
  spec.summary = 'Secure Native keypad Flutter plugin'
  spec.description = 'A native-only keypad PlatformView that exports masked state and public result codes.'
  spec.homepage = 'https://github.com/uulab-official/secure-keyboard'
  spec.license = { :type => 'MIT' }
  spec.author = { 'UULab' => 'security@uulab.dev' }
  spec.source = { :path => '.' }
  spec.platforms = { :ios => '15.0' }
  spec.swift_version = '5.9'
  spec.source_files = 'Classes/**/*.{h,m,swift}'
  spec.preserve_paths = 'Classes/SecureKeypadFFI/**/*'
  spec.public_header_files = 'Classes/SecureKeypadFFI/secure_keypad.h'
  spec.dependency 'Flutter'
  spec.frameworks = 'UIKit'
  spec.pod_target_xcconfig = {
    'SWIFT_INCLUDE_PATHS' => '$(PODS_TARGET_SRCROOT)/Classes/SecureKeypadFFI',
    'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/Classes/SecureKeypadFFI'
  }

  ffi_xcframework = ENV['SECURE_KEYPAD_FFI_XCFRAMEWORK']
  ffi_library = ENV['SECURE_KEYPAD_FFI_LIB']
  if ffi_xcframework && Dir.exist?(ffi_xcframework)
    spec.vendored_frameworks = ffi_xcframework
  elsif ffi_library && File.file?(ffi_library)
    spec.vendored_libraries = ffi_library
  else
    raise 'SECURE_KEYPAD_FFI_XCFRAMEWORK or SECURE_KEYPAD_FFI_LIB must point to matching secure_ffi artifacts before pod install'
  end
end
