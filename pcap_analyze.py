import pyshark
import datetime
import sys # connect system library
import os # connect operation system library
import codecs # connect codecs for conversation encodings

def main():
    file_exist = True
    # Dump all connections + kind of Transmission

    def vyvodIPandPayloads():
        def network_conversation(packet):
            try:
                protocol = packet.transport_layer
                source_address = packet.ip.src
                source_port = packet[packet.transport_layer].srcport
                destination_address = packet.ip.dst
                destination_port = packet[packet.transport_layer].dstport
                return (f'{protocol} {source_address}:{source_port} --> {destination_address}:{destination_port}')
            except AttributeError as e:
                pass
            # print("--- AttributeError! ---")

        print("Processing starts...")
        start_time = str(datetime.datetime.now())
        print("Start Time: " + start_time)
        conversations = []
        for packet in capture:
            results = network_conversation(packet)
            if results != None:
                conversations.append(results)
                print(results)
            else:
                pass

        print("Delete dublicates...")
        endipAdd = set(conversations)
        stop_time = str(datetime.datetime.now())

        directory = r'C:\pcap_parse\drop_all_ip_addresses.txt'
        print("Checking for directory...")
        try:
            os.remove(directory)
        except FileNotFoundError:
            pass
            # print("File not found!")
        print("Writing to file...\n")
        with open(directory, 'a') as f:
            print("[-!--ALL--IP--CONNECTIONS--!-]\n", file=f)
            print("START TIME: " + start_time, file=f)
            print("STOP TIME: " + stop_time + "\n", file=f)
            for pkt in endipAdd:
                print(pkt, file=f)

    #####################################################################################################################

    # EXPORT IMAP/POP3/IMF

    def search_imf():
        def imf_conversation_function(packet):
            try:
                time = str(packet.imf.get_field_value("date"))
                if time != "None":
                    otkuda = str(packet.imf.get_field_value("from"))
                    kuda = str(packet.imf.get_field_value("to"))
                    subject = str(packet.imf.get_field_value("subject"))
                    contenttype = str(packet.imf.get_field_value("content-type"))
                    messageid = str(packet.imf.get_field_value("message_id"))
                    mailboxlistitem = str(packet.imf.get_field_value("mailbox_list_item"))
                    return (
                                "Time (Время): " + time + "\n" + "From (Откуда): " + otkuda + "\n" + "To (Куда): " + kuda + "\n" + "Subject (Тема): " + subject + "\n" + "Content-Type: " + contenttype + "\n" + "Message-Id: " + messageid)
                else:
                    pass

            except AttributeError as e:
                pass

        print("Processing starts...")
        start_time = str(datetime.datetime.now())
        print("Start Time: " + start_time)
        forRes = []
        for packet in capture:
            resultat = imf_conversation_function(packet)
            if resultat is not None:
                forRes.append(resultat)
                print('\n' + resultat)
            else:
                pass
        stop_time = str(datetime.datetime.now())
        directory = r'C:\pcap_parse\imf_conversation_function.txt'
        print("Checking for directory...")
        try:
            os.remove(directory)
        except FileNotFoundError:
            pass
        print("Writing to file...\n")
        with open(directory, 'a') as f:
            print("[-!--POP3--IMAP--IMF--EXPORT--!-]\n", file=f)
            print("START TIME: " + start_time, file=f)
            print("STOP TIME: " + stop_time + "\n", file=f)
            for pkt in forRes:
                print('\n-------------------------------------\n', file=f)
                print(pkt, file=f)

    #####################################################################################################################

    # IMAP PROCESSING

    def imapParse():
        def imap_conversation_full_dump(packet):
            try:
                isRequest = str(packet.imap.get_field_value("isrequest"))

                if (isRequest == "1"):
                    request = str(packet.imap.get_field_value("request"))
                    request_tag = str(packet.imap.get_field_value("request_tag"))
                    tag = str(packet.imap.get_field_value("tag"))
                    request_command = str(packet.imap.get_field_value("request_command"))
                    command = str(packet.imap.get_field_value("command"))
                    request_username = str(packet.imap.get_field_value("request_username"))
                    request_password = str(packet.imap.get_field_value("request_password"))
                    destination_address = str(packet.ip.dst)
                    destination_port = str(packet[packet.transport_layer].dstport)
                    source_address = str(packet.ip.src)
                    source_port = str(packet[packet.transport_layer].srcport)
                    return (
                                "Request: " + request + "\n" + "Request Tag: " + request_tag + "\n" + "Tag: " + tag + "\n" + "Request Command: " + request_command + "\n" + "Command: " + command + "\n" + "Request Username: " + request_username + "\n" + "Request Password: " + request_password + "\n" + "Destination IP-address: " + destination_address + "\n" + "Destination Port: " + destination_port + "\n" + "Source IP-address: " + source_address + "\n" + "Source Port: " + source_port)

                elif (isRequest == "0"):
                    response = str(packet.imap.get_field_value("response"))
                    if (response != "None") and (response != ")"):
                        response_tag = str(packet.imap.get_field_value("response_tag"))
                        tag = str(packet.imap.get_field_value("tag"))
                        response_status = str(packet.imap.get_field_value("response_status"))
                        response_command = str(packet.imap.get_field_value("response_command"))
                        command = str(packet.imap.get_field_value("command"))
                        response_to = str(packet.imap.get_field_value("response_to"))
                        time = str(packet.imap.get_field_value("time"))
                        destination_address = str(packet.ip.dst)
                        destination_port = str(packet[packet.transport_layer].dstport)
                        source_address = str(packet.ip.src)
                        source_port = str(packet[packet.transport_layer].srcport)
                        return (
                                    "Response: " + response + "\n" + "Response Tag: " + response_tag + "\n" + "Tag: " + tag + "\n" + "Response Status: "
                                    + response_status + "\n" + "Response Command: " + response_command + "\n" + "Command: " + command + "\n" + "Response To: " + response_to + "\n" + "Time (Execution time): " + time + "\n"
                                    + "Destination IP-address: " + destination_address + "\n" + "Destination Port: " + destination_port + "\n" + "Source IP-address: " + source_address + "\n" + "Source Port: " + source_port)
                    else:
                        pass

            except AttributeError as e:
                pass

        print("Processing starts...")
        start_time = str(datetime.datetime.now())
        print("Start Time: " + start_time)
        forRes = []
        for packet in capture:
            resultat = imap_conversation_full_dump(packet)
            if resultat is not None:
                forRes.append(resultat)
                print('\n' + resultat)
            else:
                pass
        stop_time = str(datetime.datetime.now())
        directory = r'C:\pcap_parse\imap_processing.txt'
        print("Checking for directory...")

        try:
            os.remove(directory)
        except FileNotFoundError:
            pass
        print("Writing to file...\n")
        with open(directory, 'a') as f:
            print("[-!--IMAP--PROCESSING--!-]", file=f)
            print("START TIME: " + start_time, file=f)
            print("STOP TIME: " + stop_time + "\n", file=f)
            for pkt in forRes:
                print('\n-----------[---NEW--PACKET---]-----------\n', file=f)
                print(pkt, file=f)

    #####################################################################################################################

    # POP3 PROCESSING

    def pop3Parse():
        def pop_3_conversation_full_dump(packet):
            try:
                response = str(packet.pop.get_field_value("response"))
                if response != 'None':
                    response_indicator = str(packet.pop.get_field_value("response_indicator"))
                    response_description = str(packet.pop.get_field_value("response_description"))
                    response_data = str(packet.pop.get_field_value("response_data"))
                    destination_address = str(packet.ip.dst)
                    destination_port = str(packet[packet.transport_layer].dstport)
                    source_address = str(packet.ip.src)
                    source_port = str(packet[packet.transport_layer].srcport)
                    return (
                                "Response: " + response + "\n" + "Response Indicator: " + response_indicator + "\n" + "Response Description: " + response_description + "\n" + "Response Data: " + response_data + "\n" + "Destination IP-address: " + destination_address + "\n" + "Destination Port: " + destination_port + "\n" + "Source IP-address: " + source_address + "\n" + "Source Port: " + source_port)

                elif response == 'None':
                    request = str(packet.pop.get_field_value("request"))
                    if request != 'None':
                        request_command = str(packet.pop.get_field_value("request_command"))
                        request_parameter = str(packet.pop.get_field_value("request_parameter"))
                        destination_address = str(packet.ip.dst)
                        destination_port = str(packet[packet.transport_layer].dstport)
                        source_address = str(packet.ip.src)
                        source_port = str(packet[packet.transport_layer].srcport)
                        return (
                                    "Request: " + request + "\n" + "Request Command: " + request_command + "\n" + "Request Parameter: " + request_parameter + "\n" + "Destination IP-address: " + destination_address + "\n" + "Destination Port: " + destination_port + "\n" + "Source IP-address: " + source_address + "\n" + "Source Port: " + source_port)
                    else:
                        pass

            except AttributeError as e:
                pass

        print("Processing starts...")
        start_time = str(datetime.datetime.now())
        print("Start Time: " + start_time)
        forRes = []
        for packet in capture:
            resultat = pop_3_conversation_full_dump(packet)
            if resultat is not None:
                forRes.append(resultat)
                print('\n' + resultat)
            else:
                pass
        stop_time = str(datetime.datetime.now())
        directory = r'C:\pcap_parse\pop3_processing.txt'
        print("Checking for directory...")

        try:
            os.remove(directory)
        except FileNotFoundError:
            pass
        print("Writing to file...\n")
        with open(directory, 'a') as f:
            print("[-!--POP3--PROCESSING--!-]", file=f)
            print("START TIME: " + start_time, file=f)
            print("STOP TIME: " + stop_time + "\n", file=f)
            for pkt in forRes:
                print('\n-----------[---NEW--PACKET---]-----------\n', file=f)
                print(pkt, file=f)

    #####################################################################################################################

    if os.path.isdir("C:\pcap_parse"):
        print("Необходимый каталог для результатов существует, переходим дальше")
    else:
        print("\nВнимание! Отсутствует необходимый каталог. Создайте каталог с ссылкой: " + r"C:\pcap_parse")
        print('Инициализирован выход из программы! \n')
        sys.exit()

    name_of_file = input("Input your filename (example: " + r'C:\skp\1.pcap' + "): ")
    try:
        with codecs.open(name_of_file, 'r+', encoding='utf-8', errors='ignore') as f:
            capture = pyshark.FileCapture(f)

    except FileNotFoundError as e:
        print("--- Error! File does not exist ---\n")
        file_exist = False

    #####################################################################################################################

    while (1 > 0):

        if (file_exist == False):
            print("Внимание! Вы ввели путь к несуществующему файлу. Функции работать не будут!")

        print(
            "Choose options:\n 1 | Extract All TCP/UDP Connections \n 2 | Extract all EML \n 3 | Extract IMAP Requests And Responses \n 4 | Extract POP3 Requests And Responses \n 5 | Change File \n 6 | Clear Console \n 7 | Exit ")
        choose_option = input("Option: ")
        print("")

        if (choose_option == "1" and file_exist == True):
            print('\n --- Wait! --- \n')
            try:
                vyvodIPandPayloads()
                print("--- Option 1 end successfully! ---")
                print("Result: " + r'C:\pcap_parse\drop_all_ip_addresses.txt' + "\n")
            except BaseException as e:

                print(print(e))
        elif (choose_option == "1" and file_exist == False):
            print("Внимание. Файл не найден. Воспользуйтесь функцией Change File.")


        elif (choose_option == "6"):
            os.system('cls||clear')
            print('\n --- Clear ---')

        elif (choose_option == "7"):
            print('--- Exit --- \n')
            capture.close()
            sys.exit()

        elif (choose_option == "3" and file_exist == True):
            print('\n --- Wait! --- \n')
            try:
                imapParse()
                print("--- Option 3 end successfully! ---")
                print("Result: " + r'C:\pcap_parse\imap_processing.txt' + "\n")
            except BaseException:
                print("ERROR!")
        elif (choose_option == "3" and file_exist == False):
            print("Внимание. Файл не найден. Воспользуйтесь функцией Change File.")


        elif (choose_option == "4" and file_exist == True):
            print('\n --- Wait! --- \n')
            try:
                pop3Parse()
                print("--- Option 4 end successfully! ---")
                print("Result: " + r'C:\pcap_parse\pop3_processing.txt' + "\n")
            except BaseException:
                print("ERROR!")
        elif (choose_option == "4" and file_exist == False):
            print("Внимание. Файл не найден. Воспользуйтесь функцией Change File.")


        elif (choose_option == "2" and file_exist == True):
            print('\n --- Wait! --- \n')
            try:
                search_imf()
                print("--- Option 2 end successfully! ---")
                print("Result: " + r'C:\pcap_parse\drop_all_ip_addresses.txt' + "\n")
            except BaseException:
                print("ERROR!")
        elif (choose_option == "2" and file_exist == False):
            print("Внимание. Файл не найден. Воспользуйтесь функцией Change File.")

        elif (choose_option == "5"):
            name_of_file = input("Input your new filename (all path to file): ")
            try:
                capture = pyshark.FileCapture(name_of_file)
                print("--- New filename is: " + name_of_file + "---\n")
                file_exist = True
            except FileNotFoundError as e:
                print("--- Error! File does not exist ---\n")
                file_exist = False

if __name__ == "__main__":
    main()