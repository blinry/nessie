require "socket"
require "net/dns"

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

loop do
  data, sender_inet_addr = socket.recvfrom(999)
  type, port, domain, ip = sender_inet_addr

  query = Net::DNS::Packet::parse(data)

  p query
  name = query.question[0].qName

  addr = resolve(name)

  response = Net::DNS::Packet.new(name)
  response.header.id = query.header.id
  response.header.qr = 1
  response.header.ra = 1
  response.question = query.question
  response.answer = [Net::DNS::RR.new(name: name, ttl: 86400, cls: "IN", type: "A", address: addr)]

  socket.send(response.data, 0, ip, port)
end
