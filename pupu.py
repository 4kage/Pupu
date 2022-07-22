#!/usr/bin/env python
#

import sys
from scapy.all import *
import socket



print('                                         ')
print('############### WELCOME ! ###############')
print('                                         ')
print('             ___                         ')
print('          __/_  `.  .-"""-.              ')
print("          \_,` | \-'  /   )`-')          ")
print('           "") `"`    \  ((`"`           ')
print("          ___Y  ,    .'7 /|              ")
print("         (_,___/...-` (_/_/              ")
print('                                         ')
print('                                         ')
print('############### Woof Woof ###############')
print('                                         ')
print(' ____        ____          _  __   ___   ')
print('|  _ \ _   _|  _ \ _   _  | |/ /  / _ \  ')
print("| |_) | | | | |_) | | | | | ' /  | (_) | ")
print('|  __/| |_| |  __/| |_| | | . \   \__, | ')
print('|_|    \__,_|_|    \__,_| |_|\_\    /_/  ')
print('                                         ')
print('                                         ')
print('######################### By Nuria H.M ##')
print('                                         ')                                                       
print(' ')
print('¿Qué deseas que PuPu realice? ^^ ')
print(' ')

# Variables globales
# Modificar según preferencias
hostG = '192.168.159.135' 	# Host
rangoG = '192.168.159.0/24'	# Rango de IPs
interfaz = 'eth0'		# Interfaz de red
dstPG = 8834			# Puerto destino. Añadir rangos Ej: 80-403. Añadir varios: Ej: 21,23,80
srcPG = 30000			# Puerto origen

# Opciones de menú de Herramienta de Escaneo y Enumeración en red local
menu_options = {
    1: 'Descubrir máquinas con ARP Ping.',
    2: 'Descubrir máquinas con TCP Ping.',
    3: 'Descubrir máquinas con UDP Ping.',
    4: 'Descubrir máquinas con ICM Ping.',
    5: 'Enumerar puertos abiertos con SYN Scan',
    6: 'Enumerar puertos abiertos con TCP Connect',
    7: 'Descubrimiento de FireWall con ACK Scan',
    8: 'Banner Grabbing de Sistema Operativo',
    9: 'Salir',
}

# Imprimir menú inicial - Opciones de escaneo y enumeración
def print_menu():
    for key in menu_options.keys():
        print (key, '--', menu_options[key] )

# Opción 1: Descubrir máquinas con ARP Ping.
def option1():
     print('')
     print('############################################')
     print('')
     print('¡PuPu! ¡Descubre las máquinas en la red local!')
     print('## Opción 1: ARP Ping...##')
     print('')
     print('# PuPu:')
     print('¡En proceso!... ¡Woof, Woof! ^^')
     print('Este escaneo no suele demorarse. Pronto tendrás los resultados...')
     print('')
     scan_ARP()
     print('')
     print('¡Woof, Woof! ¡Hasta pronto! ^^')
     print('############################################')
     
# Opción 2: Descubrir máquinas con TCP Ping.     
def option2():
     print('')
     print('############################################')
     print('')
     print('¡PuPu! ¡Descubre las máquinas en la red local!')
     print('Opción 3: TCP Ping...')
     print('')     
     print('# PuPu:')
     print('¡En proceso!... ¡Woof, Woof! ^^')
     print('Este escaneo puede tardar varios minutos. Ten paciencia con PuPu...')
     print('')
     scan_TCP()
     print('')     
     print('¡Woof, Woof! ¡Hasta pronto! ^^')
     print('############################################')
          
# Opción 3: Descubrir máquinas con UDP Ping.
def option3():
     print('')
     print('############################################')
     print('')
     print('¡PuPu! ¡Descubre las máquinas en la red local!')
     print('Opción 3: UDP Ping...')
     print('')    
     print('# PuPu:')
     print('¡En proceso!... ¡Woof, Woof! ^^ ')
     print('Este escaneo puede tardar varios minutos. Ten paciencia con PuPu...')
     print('')
     scan_UDP()
     print('') 
     print('¡Woof, Woof! ¡Hasta pronto! ^^')
     print('############################################')
          
# Opción 4: Descubrir máquinas con ICM Ping.
def option4():
     print('')
     print('############################################')
     print('')
     print('¡PuPu! ¡Descubre las máquinas en la red local!')
     print('## Opción 4: ICM Ping... ##')
     print('')
     print('# PuPu:')
     print('¡En proceso!... ¡Woof, Woof! ^^')
     print('Este escaneo puede tardar varios minutos. Ten paciencia con PuPu...')
     print('')
     scan_ICM()
     print('')
     print('¡Woof, Woof! ¡Hasta pronto! ^^')
     print('############################################')
          
# Opción 5: Enumerar puertos abiertos con SYN Scan.
def option5():
     print('')
     print('############################################')
     print('')
     print('¡PuPu! ¡Enumera los puertos abiertos en la red local!')
     print('Opción 5: SYN Scan...')
     print('')
     print('# PuPu:')
     print('¡En proceso!... ¡Woof, Woof! ^^ ')
     print('')
     scan_SYN()
     print('')
     print('¡Woof, Woof! ¡Hasta pronto! ^^')
     print('############################################')
             
# Opción 6: Enumerar puertos abiertos con TCP Connect.
def option6():
     print('')
     print('############################################')
     print('')
     print('¡PuPu! ¡Enumera los puertos abiertos en la red local!')
     print('Opción 1: TCP Connect...')
     print('')
     print('# PuPu:')
     print('¡En proceso!... ¡Woof, Woof! ^^ ')
     print('')
     scan_TCP_Connect()
     print('')
     print('¡Woof, Woof! ¡Hasta pronto! ^^')
     print('############################################')
          
# Opción 7: Descubrimiento de Firewall con ACK Scan.
def option7():
     print('')
     print('############################################')
     print('')
     print('¡PuPu! ¡Realiza un descubrimiento de FireWall!')
     print('Opción 7: ACK Scan...')
     print('')
     print('# PuPu:')
     print('¡En proceso!... ¡Woof, Woof! ^^')
     print('')
     scan_ACK()
     print('')
     print('¡Woof, Woof! ¡Hasta pronto! ^^')
     print('############################################')
          
# Opción 8: Banner Grabbing de Sistema Operativo.
def option8():
     print('')
     print('############################################')
     print('')
     print('¡PuPu! ¡Realiza un Banner Grabbing!')
     print('Opción 8: Sistema Operativo...')
     print('')
     print('# PuPu:')
     print('¡En proceso!... ¡Woof, Woof! ^^')
     print('')
     banner_Grabbing()
     print('')
     print('¡Woof, Woof! ¡Hasta pronto! ^^')
     print('############################################')
     
# Escaner ARP
def scan_ARP():
	# Variables globales de Rango IP e interfaz.
	# Modificar en sección "Variables Globales" al inicio de programa.
	global rangoG
	global interfaz
	
	try:
		print('[*] PuPu comenzó a escanear con ARP Ping')
		ether = Ether(dst="ff:ff:ff:ff:ff:ff")
		arp = ARP(pdst = rangoG)
		ans, unans = srp(ether/arp, timeout = 2, iface = interfaz, inter = 0.1)
		
		# Mostrar por pantalla resumen de recibido
		for snd, rcv in ans:
			print(rcv.sprintf(r"%ARP.psrc% & %Ether.src%"))
			# Verbosidad
			print(rcv.summary())
			print('')
	# Abortar
	except KeyboardInterrupt:
		print('[*] El usuario abortó')
		print('[*] PuPu está saliendo...')
		sys.exit(1)
     		     
# Escaner TCP
def scan_TCP():
	# Variable global de Rango IP y Puerto Destino.
	# Modificar en sección "Variables Globales" al inicio de programa.
	global rangoG
	global dstPG
	print('[*] PuPu comenzó a escanear con TCP Ping')
	inactive_hosts = []
	
	try:
		ans, unans = sr(IP(dst=rangoG)/TCP(dport=dstPG,flags='S'), retry=0, timeout=1)		
		
		#Mostrar por pantalla los hosts activos
		for snd, rcv in ans:
			print(rcv.sprintf(r"%IP.src% se encuentra activo"))
		
		# Mostrar por pantalla el número de hosts inactivos
		for inactive in unans:
			inactive_hosts.append(inactive.dst)
		
		print("")
		print("#PuPu")
		print ("Un total de %d hosts se encuentran inactivos" %(len(inactive_hosts)))
		print("")

	except KeyboardInterrupt:
		print('[*] El usuario abortó')
		print('[*] PuPu está saliendo...')
		sys.exit(1)

         		     
# Escaner UDP
def scan_UDP():
	# Variable global de Rango IP y Puerto Destino.
	# Modificar en sección "Variables Globales" al inicio de programa.
	global rangoG
	global dstPG
	print('[*] PuPu comenzó a escanear con UDP Ping')
	inactive_hosts = []
	
	try:
		ans, unans = sr(IP(dst=rangoG)/UDP(dport=dstPG), retry=0, timeout=1)

		#Mostrar por pantalla los hosts activos
		for snd, rcv in ans:
			print(rcv.sprintf(r"%IP.src% se encuentra activo"))
			
		#Mostrar por pantalla los hosts activos
		for snd, rcv in ans:
			print(rcv.sprintf(r"%IP.src% se encuentra activo"))
		
		# Mostrar por pantalla el número de hosts inactivos
		for inactive in unans:
			inactive_hosts.append(inactive.dst)
		
		print("")
		print("#PuPu")
		print ("Un total de %d hosts se encuentran inactivos" %(len(inactive_hosts)))
		print("")
		
	except KeyboardInterrupt:
		print('[*] El usuario abortó')
		print('[*] PuPu está saliendo...')
		sys.exit(1)

# Escaner ICM 
def scan_ICM():
	# Variable global de Rango IP y Puerto Destino.
	# Modificar en sección "Variables Globales" al inicio de programa.
	global rangoG

	print('[*] PuPu comenzó a escanear con ICM Ping')
	inactive_hosts = []
	
	try:
		ans, unans = sr(IP(dst=rangoG)/ICMP(), retry=0, timeout=1)
		
		#Mostrar por pantalla los hosts activos
		for snd, rcv in ans:
			print(rcv.sprintf(r"%IP.src% se encuentra activo"))
		
		# Mostrar por pantalla el número de hosts inactivos
		for inactive in unans:
			inactive_hosts.append(inactive.dst)
		
		print("")
		print("#PuPu")
		print ("Un total de %d hosts se encuentran inactivos" %(len(inactive_hosts)))
		print("")
	
	except KeyboardInterrupt:
		print('[*] El usuario abortó')
		print('[*] PuPu está saliendo...')
		sys.exit(1)

# Escaner SYN
def scan_SYN():
	# Variable global de Rango IP.
	# Modificar en sección "Variables Globales" al inicio de programa.
	global hostG
	global dstPG
	
	try:
		ans, unans = sr(IP(dst=hostG)/TCP(dport=dstPG,flags='S'), retry=0, timeout=1)		
		
		#Mostrar por pantalla los puertos activos
		try:
			print("")
			print("#PuPu")
			if ans.getlayer(TCP).flags == "SA":
				print('El puerto', dstPG, 'se encuentra en escucha.')
		except AttributeError:
			print('El puerto', dstPG, 'no se encuentra en escucha.')
				
	# Abortar
	except KeyboardInterrupt:
		print('[*] El usuario abortó')
		print('[*] PuPu está saliendo...')
		sys.exit(1)

# Escaner TCP Connect
def scan_TCP_Connect():
	# Variable global de Rango IP.
	# Modificar en sección "Variables Globales" al inicio de programa.
	global hostG
	global dstPG
	
	try:
		ans, unans = sr(IP(dst=hostG)/TCP(dport=dstPG,flags='S'), retry=0, timeout=1)		
		
		#Mostrar por pantalla los puertos activos
		try:
			print("")
			print("#PuPu")
			if ans.getlayer(TCP).flags == 0x12:
				send_rst = sr(IP(dst=hostG)/TCP(dport=dstPG,flags='AR'), retry=0, timeout=1)	
				print('El puerto', dstPG, 'se encuentra en escucha.')
			elif ans.getlayer(TCP).flags == 0x14:
				print('El puerto', dstPG, 'no se encuentra en escucha.')
		except AttributeError:
			print('El puerto', dstPG, 'no se encuentra en escucha.')
				
	# Abortar
	except KeyboardInterrupt:
		print('[*] El usuario abortó')
		print('[*] PuPu está saliendo...')
		sys.exit(1)

# Escaner ACK
def scan_ACK():
	# Variables globales de Rango IP e interfaz.
	# Modificar en sección "Variables Globales" al inicio de programa.
	global hostG
	global dstPG
	global srcPG
	
	try:
		print('[*] PuPu comenzó a escanear con ACK Scan')
		ip = IP(dst='192.168.159.135')
		tcp = TCP(sport=srcPG,dport=dstPG,flags='A')		
		p = ip/tcp
		r = sr(p,timeout=1)
		
		if (str(type(r))=="<type 'NoneType'>"):
			print('')
			print('#PuPu:')
			print('No veo un Firewall. Puede que no esté filtrado')
			print('')
		else:
			print('')
			print('#PuPu:')
			print('Parece que hay un Firewall. Puede que esté filtrado')
			print('')

	except KeyboardInterrupt:
		print('[*] El usuario abortó')
		print('[*] PuPu está saliendo...')
		sys.exit(1)

# Escaner Banner Grabbing
def banner_Grabbing():
	# Variables globales de Rango IP e interfaz.
	# Modificar en sección "Variables Globales" al inicio de programa.
	global hostG
	global dstPG

	try:
		s = socket.socket()
		s.connect((hostG, int(dstPG)))
		print(s.recv(1024))

	except KeyboardInterrupt:
		print('[*] El usuario abortó')
		print('[*] PuPu está saliendo...')
		sys.exit(1)
				
if __name__=='__main__':
    # Descomentar para loop de menú. En caso de comentar, el programa se cierra tras finalizar la operación.
    #while(True):
        print_menu()
        option = ''
        try:
            option = int(input('# Introduce tu elección: '))
        except:
            print(' ')
            print('# ¡Woof, Woof! ¡Por favor, introduce un número! ^^')
            print(' ')            
        #Verificar la opción introducida y actuar en consecuencia
        if option == 1:
           option1()
        elif option == 2:
            option2()
        elif option == 3:
            option3()
        elif option == 4:
            option4()  
        elif option == 5:
            option5()  
        elif option == 6:
            option6()              
        elif option == 7:
            option7()              
        elif option == 8:
            option8()                                      
        elif option == 9:
            print(' ')
            print('# PuPu:')
            print('¡Woof, Woof! ¡Hasta pronto! ^^')
            print('############################################')            
            exit()
        else:
            print(' ')
            print('# PuPu:')
            print('¡Woof, Woof! Por favor, introduce una opción entre 1 y 9.')
            print(' ')
