require "socket"
require "bindata"

class DNSQuery < BinData::Record
  endian :big
  uint16 :transaction_id
  uint16 :flags
  uint16 :questions
  uint16 :answer_rrs
  uint16 :authority_rrs
  uint16 :additional_rrs
  stringz :name
  uint16 :query_type
  uint16 :query_class
end

class DNSResponse < BinData::Record
  endian :big
  uint16 :transaction_id
  uint16 :flags
  uint16 :questions
  uint16 :answer_rrs
  uint16 :authority_rrs
  uint16 :additional_rrs

  stringz :name
  uint16 :query_type
  uint16 :query_class

  stringz :response_name
  uint16 :response_type
  uint16 :response_class
  uint32 :ttl
  uint16 :resp_len
  uint32 :addr
end

socket = UDPSocket.new
socket.bind("127.0.0.1", 53)

loop do
  query, sender_inet_addr = socket.recvfrom(999)
  type, port, domain, ip = sender_inet_addr

  q = DNSQuery.read(query)
  p q

  r = DNSResponse.read(query)

  r.transaction_id = q.transaction_id
  r.flags = 0x8180
  r.answer_rrs = 1
  r.additional_rrs = 0

  r.response_name = q.name
  r.response_type = 1
  r.response_class = 1
  r.ttl = 86400
  r.resp_len = 4
  # Convert IP address to uint32.
  r.addr = [185, 207, 107, 49].pack("C*").unpack("N")[0]
  p r

  socket.send(r.to_binary_s, 0, ip, port)
end
