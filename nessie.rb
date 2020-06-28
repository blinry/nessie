require "socket"
require "net/dns"
require "bindata"

class Question < BinData::Record
  endian :big
  stringz :name
  uint16 :query_type
  uint16 :query_class
end

class DNSQuery < BinData::Record
  endian :big
  uint16 :transaction_id
  uint16 :flags
  uint16 :num_questions
  uint16 :answer_rrs
  uint16 :authority_rrs
  uint16 :additional_rrs

  array :questions, type: :question, initial_length: :num_questions
end

class DNSResponse < BinData::Record
  endian :big
  uint16 :transaction_id
  uint16 :flags
  uint16 :num_questions
  uint16 :answer_rrs
  uint16 :authority_rrs
  uint16 :additional_rrs

  array :questions, type: :question, initial_length: :num_questions

  stringz :response_name
  uint16 :response_type
  uint16 :response_class
  uint32 :ttl
  uint16 :resp_len
  uint32 :addr
end

def resolve(name)
  t = "199.7.83.42" # l.root-servers.net, operated by ICANN
  10.times do
    q = Net::DNS::Packet.new(name)
    s = UDPSocket.new
    s.connect(t, 53)
    s.send(q.data, 0)
    a_data = s.recvfrom(999)
    a = Net::DNS::Packet::parse(a_data)
    p a

    if a.answer.size > 0
      rr = a.answer.find { |rr| rr.type == "A" }
      if rr
        t = rr.address
        return t.to_s if rr.name == name
      else
        rr = a.answer.find { |rr| rr.type == "CNAME" }
        if rr
          n = rr.cname
          t = resolve(n)
          return t
        else
          raise "oh no"
        end
      end
    elsif a.additional.size > 0
      t = a.additional.find { |rr| rr.type == "A" }.address
    elsif a.authority.size > 0
      rr = a.authority.find { |rr| rr.type == "NS" }
      if rr
        n = rr.nsdname
        t = resolve(n)
      else
        rr = a.authority.find { |rr| rr.type == "SOA" }
        if rr
          n = rr.mname
          t = resolve(n)
        else
          raise "oh no"
        end
      end
    end
    t = t.to_s
    p t
  end
  t
end

socket = UDPSocket.new
socket.bind("127.0.0.1", 5353)

def name_to_s(name)
  b = name.bytes
  fields = []
  while b.size > 0
    l = b.shift
    fields << b.shift(l)
  end
  fields.join(".")
end

loop do
  data, sender_inet_addr = socket.recvfrom(999)
  type, port, domain, ip = sender_inet_addr

  query = DNSQuery.read(data)
  p query
  name = name_to_s(query.questions[0].name)

  addr = resolve(name)

  response = DNSResponse.new()
  response.transaction_id = query.transaction_id
  response.response_type = 1
  response.response_class = 1
  response.ttl = 86400
  response.resp_len = 4
  response.num_questions = 1
  response.answer_rrs = 1
  response.questions = query.questions
  response.response_name = query.questions[0].name
  # Convert IP address to uint32.
  response.addr = addr.split(".").map(&:to_i).pack("C*").unpack("N")[0]

  socket.send(response.to_binary_s, 0, ip, port)
end
