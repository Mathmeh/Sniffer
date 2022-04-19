# Sniffer

Консольное .Net приложение для перехвата tcp и udp пакетов на определенном устройстве и вывода о них краткой информации, c возможностью установки фильтров

# Запуск
    start sniffer -pr tcp
# Возможные параметры
* -pr  (обязателен)
  * tcp
  * udp
* -sip
  * IP адрес отправителя(source IP)
* -dip
  * IP адрес назначения(destination IP)
* -sp
  * номер порта отправителя (source port)
* -dp
  * номер порта получателя (destination port)
# Пример
    start sniffer -pr tcp -dp 80 -dip 127.0.0.1
   ![Image alt](https://github.com/Mathmeh/Sniffer/blob/master/s.png)


# Использовались
Помимо .Net 6.0 в проекте использовались: 
- [SharpPcap](https://github.com/dotpcap/sharppcap)
- [MatthiWare.CommandLineParser](https://github.com/MatthiWare/CommandLineParser.Core)






