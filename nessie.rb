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
    q = DNSPacket.new()
    q.transaction_id = rand(2 ** 16)
    q.flags = 0x0120 # standard query
    q.num_questions = 1
    question = Question.new()
    question.name = name
    question.query_type = 1
    question.query_class = 1
    q.questions = [question]

    s = UDPSocket.new
    s.connect(t, 53)
    s.send(q.to_binary_s, 0)
    p "Querying #{t} for #{name_to_s(name)}"
    STDOUT.flush
    a_data = s.recvfrom(9999)
    a = Net::DNS::Packet::parse(a_data)
    p a

    if a.answer.size > 0
      rr = a.answer.find { |rr| rr.type == "A" }
      if rr
        t = rr.address
        return t.to_s if rr.name == name_to_s(name) + "."
      else
        rr = a.answer.find { |rr| rr.type == "CNAME" }
        if rr
          n = rr.cname
          t = resolve(s_to_name(n))
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
        t = resolve(s_to_name(n))
      else
        rr = a.authority.find { |rr| rr.type == "SOA" }
        if rr
          n = rr.mname
          t = resolve(s_to_name(n))
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
    fields << b.shift(l).map(&:chr).join()
  end
  fields.join(".")
end

def s_to_name(name)
  name.split(".").map { |f|
    f.size.chr + f
  }.join()
end

loop do
  data, sender_inet_addr = socket.recvfrom(9999)
  type, port, domain, ip = sender_inet_addr

  query = DNSPacket.read(data)
  p query
  #name = name_to_s(query.questions[0].name)
  name = query.questions[0].name

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
