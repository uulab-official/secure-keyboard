Pod::Spec.new do |spec|
  spec.name = 'secure_keypad_flutter'
  spec.version = '0.1.0'
  spec.summary = 'Secure Native keypad Flutter plugin'
  spec.description = 'A native-only keypad PlatformView that exports masked state and public result codes.'
  spec.homepage = 'https://github.com/uulab-official/secure-keyboard'
  spec.license = { :type => 'MIT' }
  spec.author = { 'UULab' => 'security@uulab.dev' }
  spec.source = { :path => '.' }
  spec.platforms = { :ios => '15.1' }
  spec.swift_version = '5.9'
  spec.source_files = 'Classes/**/*.{h,m,swift}'
  spec.preserve_paths = [
    'Classes/SecureKeypadFFI/**/*',
    'secure_ffi.xcframework',
    'libsecure_ffi.a'
  ]
  spec.public_header_files = 'Classes/SecureKeypadFFI/secure_keypad.h'
  spec.dependency 'Flutter'
  spec.frameworks = 'UIKit'
  spec.pod_target_xcconfig = {
    'SWIFT_INCLUDE_PATHS' => '$(PODS_TARGET_SRCROOT)/Classes/SecureKeypadFFI',
    'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/Classes/SecureKeypadFFI'
  }

  ffi_xcframework = ENV['SECURE_KEYPAD_FFI_XCFRAMEWORK']
  ffi_library = ENV['SECURE_KEYPAD_FFI_LIB']
  staged_xcframework = File.join(__dir__, 'secure_ffi.xcframework')
  staged_library = File.join(__dir__, 'libsecure_ffi.a')
  if ffi_xcframework
    if Dir.exist?(ffi_xcframework) && Dir.exist?(staged_xcframework)
      spec.vendored_frameworks = 'secure_ffi.xcframework'
    else
      raise 'SECURE_KEYPAD_FFI_XCFRAMEWORK must point to an existing artifact matching the staged package XCFramework'
    end
  elsif ffi_library
    if File.file?(ffi_library) && File.file?(staged_library)
      spec.vendored_libraries = 'libsecure_ffi.a'
    else
      raise 'SECURE_KEYPAD_FFI_LIB must point to an existing artifact matching the staged package library'
    end
  elsif Dir.exist?(staged_xcframework)
    spec.vendored_frameworks = 'secure_ffi.xcframework'
  elsif File.file?(staged_library)
    spec.vendored_libraries = 'libsecure_ffi.a'
  else
    raise 'SECURE_KEYPAD_FFI_XCFRAMEWORK or SECURE_KEYPAD_FFI_LIB must be provided, or matching bundled secure_ffi artifacts must be present before pod install'
  end
end
