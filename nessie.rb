require "socket"
require "net/dns"
require "bindata"

class Question < BinData::Record
  endian :big
  stringz :name
  uint16 :query_type
  uint16 :query_class
end

class RR < BinData::Record
  endian :big
  stringz :name
  uint16 :rr_type
  uint16 :rr_class
  uint32 :ttl
  uint16 :resp_len
  uint32 :addr
end

class DNSPacket < BinData::Record
  endian :big
  uint16 :transaction_id
  uint16 :flags
  uint16 :num_questions
  uint16 :num_answers
  uint16 :num_authorities
  uint16 :num_additionals

  array :questions, type: :question, initial_length: :num_questions
  array :answers, type: :rr, initial_length: :num_answers
  array :authorities, type: :rr, initial_length: :num_authorities
  array :additionals, type: :rr, initial_length: :num_additionals
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

  query = DNSPacket.read(data)
  p query
  name = name_to_s(query.questions[0].name)

  addr = resolve(name)

  response = DNSPacket.new()
  response.flags = 0x8180
  response.transaction_id = query.transaction_id
  response.num_questions = 1
  response.num_answers = 1
  response.questions = query.questions

  answer = RR.new()
  answer.name = query.questions[0].name
  answer.rr_type = 1
  answer.rr_class = 1
  answer.ttl = 86400
  answer.resp_len = 4
  # Convert IP address to uint32.
  answer.addr = addr.split(".").map(&:to_i).pack("C*").unpack("N")[0]
  response.answers = [answer]

  socket.send(response.to_binary_s, 0, ip, port)
end
