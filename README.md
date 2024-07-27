# networkCapture
Script: Captura de pacotes em interface de rede declarada
-
Requisitos: 
instalação python 3.7
Lib scapy

#Sintaxe:
python dir/script.py

#Como descobrir interfaces existentes:
Acesse o CMD, se Windows e execute o comando ipconfig
Se Unix, via terminal, execute o comando ifconfig

O script usa como input o nome da interface que passará pelo sniffer e o tempo, em segundos, que essa captura deverá ocorrer.

