# Packet sniffer in python
# For Linux - Sniffs all incoming and outgoing packets :)


import socket, sys
from struct import *

#Converte  a string de 6 caracteres do endereco ethernet para base hexadecimal
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b


try: #tratamento de erros. Impede que o socket. Verifica se ha erros no soquete
	s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
	print 'Socket nao pode ser criado: Mensagem de erro : ' + str(msg[0]) + ' Mensagem ' + msg[1]
	sys.exit()


while True: # quando o pacote eh recebido
	packet = s.recvfrom(65565)
	

	packet = packet[0] #o pacote eh recebido como tupla. Assim, usa-se apenas a string da tupla
	
	
	eth_length = 14 #utiliza-se o cabecalho ethernet, que possui numero 14
	
	eth_header = packet[:eth_length] #a partir das informacoes do cabecalho recem convertido para hexadecimal, sao extraidas ifnromacoes acerca do header ethernet
	eth = unpack('!6s6sH' , eth_header)
	eth_protocol = socket.ntohs(eth[2]) #o protocolo usado eh identificado
	print 'Destino (MAC) : ' + eth_addr(packet[0:6]) + ' Origem (MAC) : ' + eth_addr(packet[6:12]) + ' Protocolo : ' + str(eth_protocol)


	if eth_protocol == 8 : #caso em que o protocolo eh 8
		ip_header = packet[eth_length:20+eth_length] #pega os 20 primeiros caracteres do cabecalho de ip
		

		iph = unpack('!BBHHHBBH4s4s' , ip_header) 	#agora ele eh descompactado

		version_ihl = iph[0]  #verifica-se a versao do protocolo ip
		version = version_ihl >> 4 #a versao do protocolo eh formatada para melhor exibicao
		ihl = version_ihl & 0xF #a versao do protocolo eh formatada para melhor exibicao

		iph_length = ihl * 4  #o tamanho do cabecalho ip eh recebido

		ttl = iph[5] #ttl eh setado
		protocol = iph[6] #prtocolo eh setado eh setado
		s_addr = socket.inet_ntoa(iph[8]);  #endereco de inicio
		d_addr = socket.inet_ntoa(iph[9]); #endereco de destino

		print 'Versao : ' + str(version) + ' Tamanho cabecalho IP: ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocolo : ' + str(protocol) + ' Endereco de origem : ' + str(s_addr) + ' Endereco de destino: ' + str(d_addr)

		
		if protocol == 6 : 	#Se for protocolo TCP
			t = iph_length + eth_length #o cabecalho do ip eh iniciado. Tal cabecalho comeca depois do cabecalho ip
			tcp_header = packet[t:t+20] #o pacote hexadecimal eh decodificado e e as informacoes do seu cabecalho tcp sao extraidas

			
			tcph = unpack('!HHLLBBHHH' , tcp_header)#as informacoes sdo pacote TCP sao extraidas
			
			source_port = tcph[0] #porta de origem
			dest_port = tcph[1] #porta de destino
			sequence = tcph[2]
			acknowledgement = tcph[3] #onde a confirmacao do recebimento do pacote eh armazenado
			doff_reserved = tcph[4]
			tcph_length = doff_reserved >> 4 #o tamanho do cabecalho eh formatado para melhor visualizacao
			
			print 'Porta de Origem: ' + str(source_port) + ' Porta de Destino : ' + str(dest_port) + ' Sequencia numerica : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' Tamanho do cabecalho TCP : ' + str(tcph_length)
			
			h_size = eth_length + iph_length + tcph_length * 4 #o tamanho de todos os cabecalhos sao contados aqui
			data_size = len(packet) - h_size #o tamanho dos cabecalhos eh subtratido do tamanho total do pacote
			
		
			data = packet[h_size:] #data recebe os dados do pacote
			
			print 'Data : ' + data

		#caso seja ICMP
		elif protocol == 1 :
			u = iph_length + eth_length #o cabecalho inicia apos o endereco de ip e ethernet
			icmph_length = 4 #o tamanho do cabcecalho icmp eh setado
			icmp_header = packet[u:u+4] #as informacoes do cabecalho icmp sao efetivamente armazenadas aqui

		
			icmph = unpack('!BBH' , icmp_header) #o pacote eh descompactado
			
			icmp_type = icmph[0] #tipo do icpm
			code = icmph[1] #codigo icmp
			checksum = icmph[2] #checksum do icmp
			
			print 'Tipo : ' + str(icmp_type) + ' Codidgo : ' + str(code) + ' Checksum : ' + str(checksum)
			
			h_size = eth_length + iph_length + icmph_length
			data_size = len(packet) - h_size
			
		
			data = packet[h_size:] #a variavel recebe os dados do pacote 
			
			print 'Data : ' + data

	
		elif protocol == 17 : #Pacotes UDP
			u = iph_length + eth_length  # similar aos outros casos, o cabecalho UDP comeca apos ip e ethernet
			udph_length = 8 #tamanho do cabecalho udp
			udp_header = packet[u:u+8] #a variavel recebe as informacoes do cabecalho

		
			udph = unpack('!HHHH' , udp_header) #as informacoes sao extraidas do pacote
			
			source_port = udph[0] #porta de origem
			dest_port = udph[1]  #porta de destino
			length = udph[2]     #tamanho do cabecalho + dados
			checksum = udph[3]   #checksum do udp
			
			
			print 'POrta de origem : ' + str(source_port) + ' Porta de destino : ' + str(dest_port) + ' Tamanho : ' + str(length) + ' Checksum : ' + str(checksum)
			
			h_size = eth_length + iph_length + udph_length #o tamanho de todos os cabecalhos sao contabilizados
			data_size = len(packet) - h_size #o tamanho da dos dados do pacote eh contabilizado
			

			data = packet[h_size:] #recebe os dados do pacote
			
			print 'Dados : ' + data

	#Caso esteja-se usando algum outro protocolo
		else :
			print 'Protocol nao suportado'
			
		print