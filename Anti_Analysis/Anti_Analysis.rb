require 'ffi'
require 'win32/registry'
require 'win32ole'

module Anti_Analysis
  extend FFI::Library
  ffi_lib 'kernel32'

  # sys_info struct
  class SYSTEM_INFO < FFI::Struct
    layout :wProcessorArchitecture, :uint16,
           :wReserved, :uint16,
           :dwPageSize, :uint32,
           :lpMinimumApplicationAddress, :pointer,
           :lpMaximumApplicationAddress, :pointer,
           :dwActiveProcessorMask, :pointer,
           :dwNumberOfProcessors, :uint32,
           :dwProcessorType, :uint32,
           :dwAllocationGranularity, :uint32,
           :wProcessorLevel, :uint16,
           :wProcessorRevision, :uint16
  end

  # memstatex struct
  class MEMORYSTATUSEX < FFI::Struct
    layout :dwLength, :uint32,
           :dwMemoryLoad, :uint32,
           :ullTotalPhys, :uint64,
           :ullAvailPhys, :uint64,
           :ullTotalPageFile, :uint64,
           :ullAvailPageFile, :uint64,
           :ullTotalVirtual, :uint64,
           :ullAvailVirtual, :uint64,
           :ullAvailExtendedVirtual, :uint64
  end

  attach_function :GetSystemInfo, [:pointer], :void
  attach_function :GlobalMemoryStatusEx, [:pointer], :bool
end

def cpucheck
  info = Anti_Analysis::SYSTEM_INFO.new
  Anti_Analysis.GetSystemInfo(info.pointer)
  if info[:dwNumberOfProcessors] < 2
    puts "[*] [CPU CHECK] Possibly a virtualised environment"
  else
    puts "[*] [CPU CHECK] Not virtualised environment"
end
end

def ramcheck
  info = Anti_Analysis::MEMORYSTATUSEX.new
  info[:dwLength] = Anti_Analysis::MEMORYSTATUSEX.size
  unless Anti_Analysis.GlobalMemoryStatusEx(info.pointer)
    puts "GlobalMemoryStatusEx Failed"
    return
  end

  if info[:ullTotalPhys] <= 2 * 1073741824
    puts "[*] [RAM CHECK] Possibly a virtualised environment"
  else
    puts "[*] [RAM CHECK] Not virtualised environment"
  end
end


def checkprocesses
  system = WIN32OLE.connect('winmgmts://')
  processes = system.ExecQuery('Select * from Win32_Process')
  proccount = processes.count
  if proccount <= 50
    puts "[*] [PROC CHECK] Possibly a sandbox environment"
  else
    puts "[*] [PROC CHECK] Not virtualised environment"
  end
end

def main
  ramcheck
  cpucheck
  checkprocesses
end

main
