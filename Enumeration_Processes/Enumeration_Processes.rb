put = `tasklist /fo csv /nh`
puts "Process | PID"
put.each_line do |line|
  prts = line.split('","') 
  next if prts.size < 2 
  pid = prts[1].strip.delete('"')
  name = prts[0].strip.delete('"')
  puts "Process: #{name} | PID: #{pid}"
end
