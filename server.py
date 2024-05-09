from dnslib import *
import socket
import time
import json

ROOT_ADDRESS = '8.8.8.8'
ROOT_PORT = 53

HOST_ADDRESS = '127.0.0.1'
HOST_PORT = 53

CACHE_PATH = 'cache.txt'

MAX_TTL_DURATION = 604800     #week in seconds

class Cache:
    def __init__(self):
        self.storage = {}
        
        with open(CACHE_PATH) as file:
            now = time.time()
            
            for line in file:
                args = line.split()
                
                domain = args[0]
                ip = args[1]
                ttl = float(args[2])
                
                if now - ttl > MAX_TTL_DURATION:
                    continue
                
                self.storage[domain] = {'ip': ip, 'ttl': ttl}
    
    def __getitem__(self, domain: str):
        return self.storage[domain]
    
    def __contains__(self, domain: str):
        return domain in self.storage
    
    def append(self, key, value):
        self.storage[key] = value
        self.save()
    
    def save(self):
        with open('cache.txt', 'w') as file:
            for domain, value in self.storage.items():
                file.write(domain + ' ' + value['ip'] + ' ' + str(value['ttl']) + '\n')


class DNSServer:
    def __init__(self):
        self.server = self.custom_server()
        self.cache = Cache()
    
    def custom_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((HOST_ADDRESS, HOST_PORT))
        return server


    def print_log(self, name: str, query: DNSRecord):
        questions = [{"qname": str(q.qname), "qtype": q.qtype, "qclass": q.qclass} for q in query.questions]
        answers = [{"name": str(q.rname), "type": str(q.rtype), "class": str(q.rclass), "ttl": str(q.ttl), "rdata": str(q.rdata)} for q in query.rr if q.rtype == QTYPE.A]
        authority = [a for a in query.auth]
        additional = [a for a in query.ar]

        log = {}

        log['header'] = {
            'id': query.header.id,
            'qr': query.header.qr,
            'opcode': query.header.opcode,
            'aa': query.header.aa,
            'tc': query.header.tc,
            'rd': query.header.rd,
            'ra': query.header.ra,
            'z': query.header.z,
            'rcode': query.header.rcode,
            'qdcount': len(questions),
            'ancount': len(answers),
            'nscount': len(authority),
            'arcount': len(additional)
        }

        log['questions'] = questions
        log['answers'] = answers
        log['authority'] = authority
        log['additional'] = additional

        print(name, json.dumps(log, indent=4), end='\n\n')

    def run(self):
        try:
            while True:
                query, addr = self.server.recvfrom(1024)
                response = self.resolve_query(query)
                self.print_log('answer', DNSRecord.parse(response))
                
                self.server.sendto(response, addr)
        finally:
            self.server.close()
            self.cache.save()
            
    def error_packet(self, rcode: int):
        reply = DNSRecord()
        reply.header.rcode = rcode
        return reply.pack()
    
    def resolve_query(self, rawQuery: bytes):
        try:
            query = DNSRecord.parse(rawQuery)
            self.print_log('query', query)
            
            if len(query.questions) != 1:
                print("incorrect query num:%d", len(query.questions), query)
                return self.error_packet(4)
        
            request_domain = str(query.questions[0].qname)    
            type = query.questions[0].qtype
            
            if type != QTYPE.A:
                print("incorrect question type (query:%s type:%d)", request_domain, type)
                return self.error_packet(4)
            
            reply = query.reply()
            
            if request_domain in self.cache:
                reply.add_answer(RR(request_domain, rdata=A(self.cache[request_domain]['ip'])))
                return reply.pack()

            root_response = DNSRecord.parse(query.send(ROOT_ADDRESS, port=ROOT_PORT))
            
            if len(root_response.rr) == 0:
                print("ip was not found")
                return self.error_packet(3)
            
            self.cache.append(key=request_domain, value={'ip': str(root_response.rr[0].rdata), 'ttl': time.time()})
            
            reply.add_answer(root_response.rr[0])
            return reply.pack()
        
        except DNSError:
            return self.error_packet(rcode=1)
        
        except Exception as e:
            return self.error_packet(rcode=2)
        


def main():
    dns_server = DNSServer()
    dns_server.run()

if __name__ == '__main__':
    main()
