if Gem.win_platform?
  mf = `powershell -c "whoami"`
  puts mf
  system('calc.exe')
end
