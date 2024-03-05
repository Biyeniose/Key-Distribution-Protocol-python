import socket
import sys
import threading
import RSA_code
import base64
import time
import AES_code

def handle_client(client_socket):
    session_key = "59a1b785320401ce789b75638f4c9eee"
    Ka = RSA_code.generate_nonce()
    Kb = RSA_code.generate_nonce()
    NK1 = RSA_code.generate_nonce()
    NK2 = RSA_code.generate_nonce()
    id_kdc = "c4ac26e240006cb9725ee6d377c74372"

    i = 0
    msg = input("Press enter to start receving")
    print(f"ENTERED")
    try: # USE IF for Bob and Alice, IF ID has Alice then send NK1 else NK2
        while (i != 1):
            # get PRk and PUa
            kdc_pub, kdc_priv = RSA_code.kdc_load_keys()
            bob_pub, bob_priv = RSA_code.b_load_keys()
            a_pub, a_priv = RSA_code.a_load_keys()
            b_delimiter = b'||'
            delimiter = '||'
            
            # receive ID and see if its Bob or Alice
            data = client_socket.recv(1024).decode("utf-8")

            if "Alice" in data:
                print("")
                print("ALICE sent ID")
                alice_id = data
                print("-------------------------------------------------------------------------------------")
                print(f"RECEVIED (ALICE):")
                print(f"Alice ID = {alice_id}")
                print("-------------------------------------------------------------------------------------")
                #################################################################################

                #################################################################################
                # encrypt NK1 || IDK with PUalice and send
                NK1_IDK = NK1 + delimiter + id_kdc
                encr_NK1_IDK = RSA_code.encrypt(NK1_IDK, a_pub)
                #msg = input('Press ENTER to send NK1 and IDK')
                client_socket.sendall(encr_NK1_IDK)
                print('SENT Encrypted Nonce NK1 and IDK (ALICE) ')
                print(f'Nonce NK1 = {NK1}')
                print(f'IDK = {id_kdc}')
                print("-------------------------------------------------------------------------------------")
                #################################################################################

                #################################################################################
                a_data = client_socket.recv(2048)
                print("RECEVIED (ALICE):")
                print("Encrypted NA + NK1 = ")
                print(a_data)
                print("")
                # decrypt
                decr_NA_NK1 = RSA_code.decrypt(a_data, kdc_priv)
                NA, NK1 = decr_NA_NK1.split(delimiter)
                print(f'Decrypted NA = {NA}')
                print("")
                print(f'Decrypted NK1 = {NK1}')
                print("-------------------------------------------------------------------------------------")
                #################################################################################

                #################################################################################
                # encrypt E(PUa, NK1) and send 
                encr_NK1 = RSA_code.encrypt(NK1, a_pub)
                client_socket.sendall(encr_NK1)
                print('SENT Encrypted Nonce NK1 (ALICE) ')
                print(f'Nonce NK1 = {NK1}')
                print("-------------------------------------------------------------------------------------")
                #################################################################################

                #################################################################################
                print(f"Generated Master Key of Alice and KDC Ka = {Ka}")
                # generate signature with PRK for KA
                signature = RSA_code.sign(Ka, kdc_priv)
                # join the msg and sig
                ka_sig = (Ka.encode("utf-8")) + b_delimiter + signature
                # convert the whole message to ascii format for encryption !!!!!!
                ka_sig2 = base64.b64encode(ka_sig).decode("ascii") # KEY
                print("")
                # divide it
                midpoint = len(ka_sig2) // 2
                part1 = ka_sig2[:midpoint]
                part2 = ka_sig2[midpoint:]
                #double encryption
                double_encr1 = RSA_code.encrypt(part1, a_pub)
                double_encr2 = RSA_code.encrypt(part2, a_pub)
                # join them then send
                encr_ka_sign = double_encr1 + b_delimiter + double_encr2
                msg = input('Press ENTER to send Encrypted KA with Signature')
                client_socket.sendall(encr_ka_sign)
                print("SENT Encrypted KA with Signature (ALICE)")
                print("Ka signed with KDC Private Key =")
                print(ka_sig)
                print("-------------------------------------------------------------------------------------")
                #################################################################################

                a_id = client_socket.recv(2048).decode('utf-8')
                print("PHASE 2")
                print(f"Received Alice ID = {a_id}")
                #################################################################################
                # encrypt Kab with Ka
                key_id = session_key + delimiter + a_id
                encr_sess_key = AES_code.encrypt(key_id.encode('utf-8'), Ka.encode('utf-8'))
                msg = input('Press ENTER to send session key (ALICE)')
                client_socket.sendall(encr_sess_key)
                print(f"SENT Session Key Kab and Alice ID = {key_id}")
                #################################################################################


            elif "Bob" in data:
                print("")
                print("BOB sent ID")
                bob_id = data
                print("-------------------------------------------------------------------------------------")
                print(f"RECEVEID (BOB):")
                print(f"Bob ID = {bob_id}")
                print("-------------------------------------------------------------------------------------")
                #################################################################################

                #################################################################################
                # encrypt NK2 || IDK with PU_Bob and send
                NK2_IDK = NK2 + delimiter + id_kdc
                encr_NK2_IDK = RSA_code.encrypt(NK2_IDK, bob_pub)
                #msg = input('Press ENTER to send NK1 and IDK')
                client_socket.sendall(encr_NK2_IDK)
                print('SENT Encrypted Nonce NK2 and IDK (BOB) ')
                print(f'Nonce NK2 = {NK2}')
                print(f'IDK = {id_kdc}')
                print("-------------------------------------------------------------------------------------")
                #################################################################################

                #################################################################################
                b_data = client_socket.recv(2048)
                print("RECEVIED (BOB):")
                print("Encrypted NB + NK2 = ")
                print(b_data)
                print("")
                # decrypt
                decr_NB_NK2 = RSA_code.decrypt(b_data, kdc_priv)
                NB, NK2 = decr_NB_NK2.split(delimiter)
                print(f'Decrypted NB = {NB}')
                print("")
                print(f'Decrypted NK2 = {NK2}')
                print("-------------------------------------------------------------------------------------")
                #################################################################################

                #################################################################################
                # encrypt E(PUb, NK2) and send 
                encr_NK2 = RSA_code.encrypt(NK2, bob_pub)
                client_socket.sendall(encr_NK2)
                print('SENT Encrypted Nonce NK1 (BOB) ')
                print(f'Nonce NK2 = {NK2}')
                print("-------------------------------------------------------------------------------------")
                #################################################################################

                #################################################################################
                print(f"Generated Master Key of Bob and KDC Kb = {Kb}")
                # generate signature with PRK for KB
                signature = RSA_code.sign(Kb, kdc_priv)
                # join the msg and sig
                kb_sig = (Kb.encode("utf-8")) + b_delimiter + signature
                # convert the whole message to ascii format for encryption !!!!!!
                kb_sig2 = base64.b64encode(kb_sig).decode("ascii") # KEY
                print("")
                # divide it
                midpoint = len(kb_sig2) // 2
                part1 = kb_sig2[:midpoint]
                part2 = kb_sig2[midpoint:]
                #double encryption
                double_encr1 = RSA_code.encrypt(part1, bob_pub)
                double_encr2 = RSA_code.encrypt(part2, bob_pub)
                # join them then send
                encr_kb_sign = double_encr1 + b_delimiter + double_encr2
                msg = input('Press ENTER to send Encrypted KB with Signature')
                client_socket.sendall(encr_kb_sign)
                print("SENT Encrypted KB with Signature (BOB)")
                print("Kb signed with KDC Private Key =")
                print(kb_sig)
                print("-------------------------------------------------------------------------------------")
                #################################################################################
                
                b_id = client_socket.recv(2048).decode('utf-8')
                print("PHASE 2")
                print(f"Received Bob ID = {b_id}")
                #################################################################################
                # encrypt Kab with Ka
                key_id = session_key + delimiter + b_id
                encr_sess_key = AES_code.encrypt(key_id.encode('utf-8'), Kb.encode('utf-8'))
                msg = input('Press ENTER to send session key (BOB)')
                client_socket.sendall(encr_sess_key)
                print(f"SENT Session Key Kab and Bob ID = {key_id}")
                #################################################################################

            i = 1
            print("")
            if not data:
                break

    finally:
        client_socket.close()

def run_KDC():
    RSA_code.generate_keys_kdc()
    RSA_code.generate_keys_bob()
    RSA_code.generate_keys_alice()

    if len(sys.argv) == 0:
        print("Please prvoide an arugement for the port number")
        sys.exit(1)
    else:
        port_num = sys.argv[1]
        port_num = int(port_num)
        print(f"Port Number = {port_num}")
    
    server_ip = "127.0.0.1"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((server_ip, port_num))
    server.listen(2)
    print(f"Server listening on {server_ip}:{port_num}")

    try:
        while True:
            cli_socket, cli_address = server.accept()
            print(f"Accepted client connection from: {cli_address}")
            client_handler = threading.Thread(target=handle_client, args=(cli_socket,))
            client_handler.start()
    finally:
        server.close()

if __name__ == '__main__':
    run_KDC()    