import socket
import sys
import RSA_code
import AES_code
import base64
import time

def run_client_B():
    b_pub, b_priv = RSA_code.b_load_keys()
    kdc_pub, kdc_priv = RSA_code.kdc_load_keys()
    NB = RSA_code.generate_nonce()
    b_delimiter = b'||'
    delimiter = '||'

    if len(sys.argv) == 0:
        print("Please prvoide an arugement for the port number")
        sys.exit(1)
    else:
        port_num = sys.argv[1]
        port_num = int(port_num)
        print(f"Port Number = {port_num}")
    
    bob_id = "60862951Bob"
    client_ip = "127.0.0.1"
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((client_ip, port_num))

    try:
        print("-------------------------------------------------------------------------------------")
        # send IDb to KDC
        msg = input("Press enter for Bob to send IDb: ")
        print(f'SENT Bob ID')
        print(f'Bob ID = {bob_id}')
        client_socket.send(bob_id.encode("utf-8"))
        print("-------------------------------------------------------------------------------------")

        # receive encrypted NK1 and IDK
        data_kdc = client_socket.recv(2048) # in bytes
        print("RECEIVED")
        print("Encrypted NK2 + IDK = ")
        print(data_kdc)
        print("")
        # decrypt
        decr_NK2_IDK = RSA_code.decrypt(data_kdc, b_priv)
        NK2, IDK = decr_NK2_IDK.split(delimiter)
        print(f'Decrypted NK2 = {NK2}')
        print("")
        print(f'Decrypted IDK = {IDK}')
        print("-------------------------------------------------------------------------------------")

        # encode E(PUk, [Nb || NK2]) and send
        NB_NK2 = NB + delimiter + NK2
        encr_NB_NK2 = RSA_code.encrypt(NB_NK2, kdc_pub)
        msg = input("Press Enter to send NB and NK2")
        client_socket.sendall(encr_NB_NK2) # send
        print("SENT Encrypted NB and NK2 to KDC")
        print(f'Nonce NB = {NB}')
        print("")
        print(f'NK2 = {NK2}')
        print("-------------------------------------------------------------------------------------")

        # receive encrypted NK2 
        data_kdc = client_socket.recv(2048) # in bytes
        print("RECEVIED")
        print("Encrypted NK2 = ")
        print(data_kdc)
        print("")
        # decrypt
        decr_NK2 = RSA_code.decrypt(data_kdc, b_priv)
        NK2 = decr_NK2
        print(f'Decrypted NK2 = {NK2}')
        print("-------------------------------------------------------------------------------------")

        # recevied encrypted Kb signed
        data_kdc = client_socket.recv(2048) # in bytes
        print("RECEVIED")
        print("Encrypted Kb + Signature = ")
        print(data_kdc)
        print("")
        # split initial encryption
        p1, p2 = data_kdc.split(b_delimiter)
        decr1 = RSA_code.decrypt(p1, b_priv)
        decr2 = RSA_code.decrypt(p2, b_priv)
        msg_combined = decr1 + decr2

        print("Decrypted Kb + Signature = ")
        final1 = base64.b64decode(msg_combined) # KEYYY
        print(final1)

        Kb, signature = final1.split(b_delimiter)
        print("")
        # verify signature
        if RSA_code.verify(Kb.decode('utf-8'), kdc_pub, signature):
            print("Signature VERIFIED")
            print(f"Master Key of Alice and KDC Kb = {Kb.decode('utf-8')}")
        else:
            print('Signature NOT VERIFIED')

        print("-------------------------------------------------------------------------------------")

        Kb_decode = Kb.decode('utf-8')

        # send Bob ID again
        msg = input('Press enter to send Bob ID for PHASE 2')
        client_socket.sendall(bob_id.encode('utf-8'))

        # decrypt the session key
        data_kdc = client_socket.recv(2048) # in bytes
        print("")
        print(f'RECEIVED')
        print('Decrypted Encrypted Session Key + Bob ID')
        print(data_kdc)
        print("")
        decr_data = AES_code.decrypt(data_kdc, Kb)
        sess_key, b_id = decr_data.decode('utf-8').split(delimiter)
        print(f"Session Key Kab = {sess_key}")
        print(f"Bob ID = {b_id}")


    finally:
        client_socket.close()


if __name__ == '__main__':
    run_client_B()    