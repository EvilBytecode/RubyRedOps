require 'ffi'

module Enable_All_Tokens
  extend FFI::Library
  # kernerl32.dll -> we will import getcurrentproc and lasterror incase it returns some error, we can after debug it if there are some issues
  ffi_lib 'kernel32'
  attach_function :GetCurrentProcess, [], :pointer
  attach_function :GetLastError, [], :uint32
  # advapi32.dll -> we will import openproctoken, lookupprivval and adjust token
  ffi_lib 'advapi32'
  attach_function :OpenProcessToken, [:pointer, :uint32, :pointer], :bool
  attach_function :LookupPrivilegeValueW, [:pointer, :pointer, :pointer], :bool
  attach_function :AdjustTokenPrivileges, [:pointer, :bool, :pointer, :uint32, :pointer, :pointer], :bool
  # variables that are needed to query and enable
  TOKEN_ADJUST_PRIVILEGES = 0x0020
  TOKEN_QUERY = 0x0008
  SE_PRIVILEGE_ENABLED = 0x00000002
  ERROR_NOT_ALL_ASSIGNED = 1300
  # classes y probably know lol
  class LUID < FFI::Struct
    layout :LowPart, :uint32, :HighPart, :int32
  end
  class LUID_AND_ATTRIBUTES < FFI::Struct
    layout :Luid, LUID, :Attributes, :uint32
  end
  class TOKEN_PRIVILEGES < FFI::Struct
    layout :PrivilegeCount, :uint32, :Privileges, [LUID_AND_ATTRIBUTES, 1]
  end
end
# tokens that we will enable, you can add or remove some its obv on y
tokens = [
  "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
  "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
  "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
  "SeDebugPrivilege", "SeDelegateSessionUserImpersonatePrivilege", "SeEnableDelegationPrivilege",
  "SeImpersonatePrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseBasePriorityPrivilege",
  "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege",
  "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege",
  "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege",
  "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemtimePrivilege",
  "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeTakeOwnershipPrivilege",
  "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege"
]
hProcess = Enable_All_Tokens.GetCurrentProcess
hToken = FFI::MemoryPointer.new(:pointer)
if Enable_All_Tokens.OpenProcessToken(hProcess, Enable_All_Tokens::TOKEN_ADJUST_PRIVILEGES | Enable_All_Tokens::TOKEN_QUERY, hToken)
  tokens.each do |token|
    luid = Enable_All_Tokens::LUID.new
    token_ptr = FFI::MemoryPointer.from_string(token.encode('UTF-16LE'))
    if Enable_All_Tokens.LookupPrivilegeValueW(nil, token_ptr, luid)
      tp = Enable_All_Tokens::TOKEN_PRIVILEGES.new
      tp[:PrivilegeCount] = 1
      tp[:Privileges][0][:Luid] = luid
      tp[:Privileges][0][:Attributes] = Enable_All_Tokens::SE_PRIVILEGE_ENABLED
      if Enable_All_Tokens.AdjustTokenPrivileges(hToken.read_pointer, false, tp, 0, nil, nil)
        puts Enable_All_Tokens.GetLastError == Enable_All_Tokens::ERROR_NOT_ALL_ASSIGNED ? "The privilege #{token} was not assigned." : "The privilege #{token} was successfully adjusted."
      else
        puts "err adjusting token privileges for #{token}: #{Enable_All_Tokens.GetLastError}"
      end
    else
      puts "err looking up privilege value for #{token}: #{Enable_All_Tokens.GetLastError}"
    end
  end
else
  puts "err opening process token: #{Enable_All_Tokens.GetLastError}"
end
gets # btw this is pause so you can check in proc hacker or sys informer or wtv modified ver of taskmgr you use lol

