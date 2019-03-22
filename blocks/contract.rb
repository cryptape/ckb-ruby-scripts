# This contract needs 2 signed arguments:
# 0. chain name, this is just a placeholder to distinguish between chains,
# it will not be used in the actual contract. The pair of chain name and
# pubkey uniquely identifies a chain.
# 1. pubkey
# This contract might also need 1 unsigned argument:
# 2. signature
if ARGV.length != 3
  raise "Not enough arguments!"
end

def hex_to_bin(s)
  if s.start_with?("0x")
    s = s[2..-1]
  end
  [s].pack("H*")
end

contract_type_hash = CKB.load_script_hash(0, CKB::Source::CURRENT, CKB::Category::TYPE)

tx = CKB.load_tx

matched_inputs = []
matched_outputs = []

blake2b = Blake2b.new
blake2b.update(contract_type_hash)
tx["inputs"].each_with_index do |input, i|
  if CKB.load_script_hash(i, CKB::Source::INPUT, CKB::Category::TYPE) == contract_type_hash
    matched_inputs << i
    blake2b.update(CKB::CellField.new(CKB::Source::INPUT, i, CKB::CellField::DATA).read(0, 72))
  end
end
tx["outputs"].each_with_index do |output, i|
  hash = CKB.load_script_hash(i, CKB::Source::OUTPUT, CKB::Category::TYPE)
  if hash == contract_type_hash
    matched_outputs << i
    blake2b.update(CKB::CellField.new(CKB::Source::OUTPUT, i, CKB::CellField::DATA).read(0, 72))
  end
end

data = blake2b.final

unless Secp256k1.verify(hex_to_bin(ARGV[1]), hex_to_bin(ARGV[2]), data)
  raise "Signature verification error!"
end

if !(matched_inputs.size == 0 or matched_inputs.size == 1)
  raise "Wrong number of matched inputs!"
end

if matched_outputs.size != 1
  raise "Wrong number of matched outputs!"
end

# first commit
if matched_inputs.size == 0
  # Data = [confirmed_root, unconfirmed_root, blockNumber]
  # 32, 32, 8 = 72Bytes
  data = CKB::CellField.new(CKB::Source::OUTPUT, matched_inputs[0], CKB::CellField::DATA).read(0, 72)
  confirmed, unconfirmed, block_number = data.unpack("H64H64Q<")

  if confirmed != "0000000000000000000000000000000000000000000000000000000000000000"
    raise "If first commit, expected 0000000000000000000000000000000000000000000000000000000000000000, but got #{confirmed}"
  end
end

if matched_inputs.size == 1
  data = CKB::CellField.new(CKB::Source::INPUT, matched_inputs[0], CKB::CellField::DATA).read(0, 72)
  input_confirmed, input_unconfirmed, input_block_number = data.unpack("H64H64Q<")

  data = CKB::CellField.new(CKB::Source::OUTPUT, matched_outputs[0], CKB::CellField::DATA).read(0, 72)
  output_confirmed, output_unconfirmed, output_block_number = data.unpack("H64H64Q<")
  
  unless output_block_number == input_block_number + 1
    raise "BlockNumber verification error!"
  end
  
  unless input_unconfirmed == output_confirmed
    raise "Confirmed root verification error!"
  end
end
