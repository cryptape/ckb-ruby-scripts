# This contract needs 2 signed arguments:
# 0. layer2 name, this is here so we can have different lock hash for
# different layer2 for ease of querying. In the actual contract this is
# not used.
# 1. pubkey, used to identify layer2 owner
# This contracts also accepts 2 required unsigned arguments and 1
# optional unsigned argument:
# 2. signature, signature used to present ownership
# 3. type, SIGHASH type
# 4. output(s), this is only used for SIGHASH_SINGLE and SIGHASH_MULTIPLE types,
# for SIGHASH_SINGLE, it stores an integer denoting the index of output to be
# signed; for SIGHASH_MULTIPLE, it stores a string of `,` separated array denoting
# outputs to sign
if ARGV.length != 4 && ARGV.length != 5
    raise "Wrong number of arguments!"
  end
  
  SIGHASH_ALL = 0x1
  SIGHASH_NONE = 0x2
  SIGHASH_SINGLE = 0x3
  SIGHASH_MULTIPLE = 0x4
  SIGHASH_ANYONECANPAY = 0x80
  
  def hex_to_bin(s)
    if s.start_with?("0x")
      s = s[2..-1]
    end
    [s].pack("H*")
  end
  
  tx = CKB.load_tx
  blake2b = Blake2b.new
  
  blake2b.update(ARGV[3])
  sighash_type = ARGV[3].to_i
  
  if sighash_type & SIGHASH_ANYONECANPAY != 0
    # Only hash current input
    out_point = CKB.load_input_out_point(0, CKB::Source::CURRENT)
    blake2b.update(out_point["hash"])
    blake2b.update(out_point["index"].to_s)
    blake2b.update(CKB::CellField.new(CKB::Source::CURRENT, 0, CKB::CellField::LOCK_HASH).readall)
  else
    # Hash all inputs
    tx["inputs"].each_with_index do |input, i|
      blake2b.update(input["hash"])
      blake2b.update(input["index"].to_s)
      blake2b.update(CKB.load_script_hash(i, CKB::Source::INPUT, CKB::Category::LOCK))
    end
  end
  
  case sighash_type & (~SIGHASH_ANYONECANPAY)
  when SIGHASH_ALL
    tx["outputs"].each_with_index do |output, i|
      blake2b.update(output["capacity"].to_s)
      blake2b.update(output["lock"])
      if hash = CKB.load_script_hash(i, CKB::Source::OUTPUT, CKB::Category::TYPE)
        blake2b.update(hash)
      end
    end
  when SIGHASH_SINGLE
    raise "Not enough arguments" unless ARGV[4]
    output_index = ARGV[4].to_i
    output = tx["outputs"][output_index]
    blake2b.update(output["capacity"].to_s)
    blake2b.update(output["lock"])
    if hash = CKB.load_script_hash(output_index, CKB::Source::OUTPUT, CKB::Category::TYPE)
      blake2b.update(hash)
    end
  when SIGHASH_MULTIPLE
    raise "Not enough arguments" unless ARGV[4]
    ARGV[4].split(",").each do |output_index|
      output_index = output_index.to_i
      output = tx["outputs"][output_index]
      blake2b.update(output["capacity"].to_s)
      blake2b.update(output["lock"])
      if hash = CKB.load_script_hash(output_index, CKB::Source::OUTPUT, CKB::Category::TYPE)
        blake2b.update(hash)
      end
    end
  end
  hash = blake2b.final
  
  pubkey = ARGV[1]
  signature = ARGV[2]
  
  unless Secp256k1.verify(hex_to_bin(pubkey), hex_to_bin(signature), hash)
    raise "Signature verification error!"
  end
  