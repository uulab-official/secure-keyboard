require 'digest'

Pod::Spec.new do |spec|
  spec.name = 'SecureKeypadKit'
  spec.version = '0.1.0'
  spec.summary = 'Secure Native keypad SDK for iOS'
  spec.description = 'A native-only UIKit keypad that exports masked state and native opaque submissions.'
  spec.homepage = 'https://github.com/uulab-official/secure-keyboard'
  spec.license = { :type => 'MIT' }
  spec.author = { 'UULab' => 'security@uulab.dev' }
  spec.source = { :path => '.' }
  spec.platforms = { :ios => '15.1' }
  spec.swift_version = '5.9'
  spec.module_name = 'SecureKeypadKit'
  spec.requires_arc = true
  spec.source_files = 'SecureKeypad*.swift'
  spec.preserve_paths = [
    'SecureKeypadFFI/**/*',
    'secure_ffi.xcframework',
    'libsecure_ffi.a'
  ]
  spec.public_header_files = 'SecureKeypadFFI/secure_keypad.h'
  spec.frameworks = ['UIKit', 'AudioToolbox']
  spec.pod_target_xcconfig = {
    'SWIFT_INCLUDE_PATHS' => '$(PODS_TARGET_SRCROOT)/SecureKeypadFFI',
    'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/SecureKeypadFFI'
  }

  ffi_xcframework = ENV['SECURE_KEYPAD_FFI_XCFRAMEWORK']
  ffi_library = ENV['SECURE_KEYPAD_FFI_LIB']
  staged_xcframework = File.join(__dir__, 'secure_ffi.xcframework')
  staged_library = File.join(__dir__, 'libsecure_ffi.a')

  same_ffi_artifact = lambda do |external_path, staged_path|
    if File.file?(external_path) && File.file?(staged_path)
      Digest::SHA256.file(external_path).digest == Digest::SHA256.file(staged_path).digest
    elsif Dir.exist?(external_path) && Dir.exist?(staged_path)
      relative_entries = lambda do |root|
        Dir.glob(File.join(root, '**', '*'), File::FNM_DOTMATCH)
          .reject { |entry| ['.', '..'].include?(File.basename(entry)) }
          .map { |entry| entry.delete_prefix("#{root}#{File::SEPARATOR}") }
          .sort
      end
      external_entries = relative_entries.call(external_path)
      staged_entries = relative_entries.call(staged_path)
      next false unless external_entries == staged_entries

      external_entries.all? do |relative_entry|
        external_entry = File.join(external_path, relative_entry)
        staged_entry = File.join(staged_path, relative_entry)
        entry_type = File.ftype(external_entry)
        next false unless entry_type == File.ftype(staged_entry)
        next false if entry_type == 'link'
        next true if entry_type == 'directory'
        next false unless entry_type == 'file'

        Digest::SHA256.file(external_entry).digest == Digest::SHA256.file(staged_entry).digest
      end
    else
      false
    end
  rescue StandardError
    false
  end

  if ffi_xcframework
    if Dir.exist?(ffi_xcframework) && Dir.exist?(staged_xcframework) && same_ffi_artifact.call(ffi_xcframework, staged_xcframework)
      spec.vendored_frameworks = 'secure_ffi.xcframework'
    else
      raise 'SECURE_KEYPAD_FFI_XCFRAMEWORK does not match the staged package FFI artifact or is missing'
    end
  elsif ffi_library
    if File.file?(ffi_library) && File.file?(staged_library) && same_ffi_artifact.call(ffi_library, staged_library)
      spec.vendored_libraries = 'libsecure_ffi.a'
    else
      raise 'SECURE_KEYPAD_FFI_LIB does not match the staged package FFI artifact or is missing'
    end
  elsif Dir.exist?(staged_xcframework)
    spec.vendored_frameworks = 'secure_ffi.xcframework'
  elsif File.file?(staged_library)
    spec.vendored_libraries = 'libsecure_ffi.a'
  else
    raise 'SECURE_KEYPAD_FFI_XCFRAMEWORK or SECURE_KEYPAD_FFI_LIB must be provided, or matching bundled secure_ffi artifacts must be present before pod install'
  end
end
