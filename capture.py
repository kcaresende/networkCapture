
from scapy.all import *


nPkt = 0
tTcp = 0
tUdp = 0
tPkt = 0
nTcp = 0
nUdp = 0
nNI = 0
tNI = 0

def capturar_pacotes():
    global tPkt
    global tTcp
    global tUdp
    global nPkt
    global nTcp
    global nUdp
    global nNI
    global tNI
    #Iniciando captura na interface declarada em iface
    #Verificar interfaces existentes no dispositivo
    interface = input("Digite a interface que será capturada: ")
    ttl= input("Informe o tempo definido para captura (segundos): ")
    print("Capturando tráfego da interface "+interface+ "....")
    sniff(iface=interface, prn=traffic_monitor_callbak, store=0, timeout=int(ttl))
    print("Quantidade de pacotes total: " + str(nPkt) + " tamanho bytes: " + str(tPkt))
    print("Quantidade de pacotes TCP: " + str(nTcp) + " tamanho bytes: " + str(tTcp))
    print("Quantidade de pacotes UDP: " + str(nUdp) + " tamanho bytes: " + str(tUdp))
    print("Quantidade de pacotes protocolo Nao Identificado: " + str(nNI) + " tamanho bytes: " + str(tNI))
    #while True:
        #print(sniff(iface="Wi-Fi",count=1, filter="tcp").summary())
        #print(sniff(prn=lambda x:x.summary()), count=1, filter="tcp")
    #    time.sleep(1)
    
    
    #interface = input("Digite o nome da interface a ser capturada: ")   
    #pacotes = sniff(iface= "Wi-Fi",count=1000) # Captura 10 pacotes de rede
    #for pacote in pacotes:
    #    print(pacote.summary()) # Imprime um resumo dos pacotes capturados

def traffic_monitor_callbak(pacote):
    global tPkt
    global tTcp
    global tUdp
    global nPkt
    global nTcp
    global nUdp
    global nNI
    global tNI


    if IP in pacote:
        tamanhoPacote = 0
        tamanhoPacote = int(pacote.sprintf("%IP.len%") if pacote.sprintf("%IP.len%") != "??" else "0")
        nPkt = nPkt + 1
        tPkt = tPkt + tamanhoPacote
        print("Origem: " + pacote.sprintf("%IP.src%") +
              " -> Destino: " + pacote.sprintf("%IP.dst%") +
              " | Protocolo:  " + pacote.sprintf("%IP.proto%") +
              " | Tamanho (bytes): " + pacote.sprintf("%IP.len%"))
        if pacote.sprintf("%IP.proto%") == "tcp":
            nTcp = nTcp + 1
            tTcp = tTcp + tamanhoPacote
        
        if pacote.sprintf("%IP.proto%") == "udp":
            nUdp = nUdp + 1
            tUdp = tUdp + tamanhoPacote
        
        if pacote.sprintf("%IP.proto%") != "udp" and pacote.sprintf("%IP.proto%") != "tcp":
            nNI = nNI + 1
            tNI = tNI + tamanhoPacote

capturar_pacotes()
print ("Fim da captura!")
