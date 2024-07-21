require 'securerandom'
require 'tempfile'

def hammerapi(num)
  bufsize = 0xFFFFF
  num.times do
    Tempfile.create('file.tmp') do |file|
      file.write(SecureRandom.random_bytes(bufsize))
      file.flush
      file.rewind
      file.read(bufsize)
    end
  end
end

def primecalc(iters)
  prime, i = 2, 0
  while i < iters
    i += 1 if (2...prime).all? { |j| prime % j != 0 }
    prime += 1
  end
end

def main
  puts "[+] First method triggered"
  begin
    hammerapi(2000)
    puts "[+] API Hammering successfully completed!"
  rescue => e
    # skibidi err catching :cool:
    puts "[!] Error during API hammering: #{e}"
  end
  puts "[+] Second method triggered"
  primecalc(2000)
end

main
