# This contract needs 1 signed arguments:
# 0. pubkey
# This contract might also need 1 unsigned argument:
# 1. signature
if ARGV.length != 2
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

if tx["inputs"].size != 1 or tx["outputs"].size != 1
  raise "Wrong number of inputs and outputs!"
end

blake2b = Blake2b.new
blake2b.update(contract_type_hash)
tx["inputs"].each_with_index do |input, i|
  if CKB.load_script_hash(i, CKB::Source::INPUT, CKB::Category::TYPE) == contract_type_hash
    blake2b.update(CKB::CellField.new(CKB::Source::INPUT, i, CKB::CellField::DATA).read(0, 72))
  end
end
tx["outputs"].each_with_index do |output, i|
  hash = CKB.load_script_hash(i, CKB::Source::OUTPUT, CKB::Category::TYPE)
  if CKB.load_script_hash(i, CKB::Source::OUTPUT, CKB::Category::TYPE) == contract_type_hash
    blake2b.update(CKB::CellField.new(CKB::Source::OUTPUT, i, CKB::CellField::DATA).read(0, 72))
  end
end

data = blake2b.final

unless Secp256k1.verify(hex_to_bin(ARGV[0]), hex_to_bin(ARGV[1]), data)
  raise "Signature verification error!"
end

# Data = [confirmed_root, unconfirmed_root, blockNumber]
# 32, 32, 8 = 72Bytes
input = tx["inputs"][0]
data = CKB::CellField.new(CKB::Source::INPUT, i, CKB::CellField::DATA).read(0, 72)
input_confirmed, input_unconfirmed, input_block_number = data.unpack("H64H64Q<")

outputs = tx["outputs"][0]
data = CKB::CellField.new(CKB::Source::INPUT, i, CKB::CellField::DATA).read(0, 72)
output_confirmed, output_unconfirmed, output_block_number = data.unpack("H64H64Q<")

unless output_block_number == input_block_number + 1
  raise "BlockNumber verification error!"
end

unless input_unconfirmed == output_confirmed
  raise "Confirmed root verification error!"
end
