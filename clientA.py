import socket
import sys
import RSA_code
import AES_code
import base64
import time

# decrypt first with PRa Alice priv key
# decrypt again with PUk KDC pub key
def run_client_A():
    a_pub, a_priv = RSA_code.a_load_keys()
    kdc_pub, kdc_priv = RSA_code.kdc_load_keys()
    NA = RSA_code.generate_nonce()
    b_delimiter = b'||'
    delimiter = '||'

    if len(sys.argv) == 0:
        print("Please prvoide an arugement for the port number")
        sys.exit(1)
    else:
        port_num = sys.argv[1]
        port_num = int(port_num)
        print(f"Port Number = {port_num}")
    
    alice_id = "417825093Alice"
    client_ip = "127.0.0.1"
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((client_ip, port_num))

    try:
        print("-------------------------------------------------------------------------------------")
        # send IDa to KDC
        msg = input("Press enter for Alice to send IDa: ")
        print(f'SENT Alice ID')
        print(f'Alice ID = {alice_id}')
        client_socket.send(alice_id.encode("utf-8"))
        print("-------------------------------------------------------------------------------------")

        # receive encrypted NK1 and IDK
        data_kdc = client_socket.recv(2048) # in bytes
        print("RECEVIED")
        print("Encrypted NK1 + IDK = ")
        print(data_kdc)
        print("")
        # decrypt
        decr_NK1_IDK = RSA_code.decrypt(data_kdc, a_priv)
        NK1, IDK = decr_NK1_IDK.split(delimiter)
        print(f'Decrypted NK1 = {NK1}')
        print("")
        print(f'Decrypted IDK = {IDK}')
        print("-------------------------------------------------------------------------------------")

        # encode E(PUk, [Na || NK1]) and send
        NA_NK1 = NA + delimiter + NK1
        encr_NA_NK1 = RSA_code.encrypt(NA_NK1, kdc_pub)
        msg = input("Press Enter to send NA and NK1")
        client_socket.sendall(encr_NA_NK1) # send
        print("SENT Encrypted NA and NK1 to KDC")
        print(f'Nonce NA = {NA}')
        print(f'NK1 = {NK1}')
        print("-------------------------------------------------------------------------------------")

        # receive encrypted NK1 
        data_kdc = client_socket.recv(2048) # in bytes
        print("RECEVIED")
        print("Encrypted NK1 = ")
        print(data_kdc)
        print("")
        # decrypt
        decr_NK1 = RSA_code.decrypt(data_kdc, a_priv)
        NK1 = decr_NK1
        print(f'Decrypted NK1 = {NK1}')
        print("-------------------------------------------------------------------------------------")

        # recevied encrypted Ka signed
        data_kdc = client_socket.recv(2048) # in bytes
        print("RECEVIED")
        print("Encrypted Ka + Signature = ")
        print(data_kdc)
        print("")
        # split initial encryption
        p1, p2 = data_kdc.split(b_delimiter)
        decr1 = RSA_code.decrypt(p1, a_priv)
        decr2 = RSA_code.decrypt(p2, a_priv)
        msg_combined = decr1 + decr2

        print("Decrypted Ka + Signature = ")
        final1 = base64.b64decode(msg_combined) # KEYYY
        print(final1)

        Ka, signature = final1.split(b_delimiter)
        print("")
        # verify signature
        if RSA_code.verify(Ka.decode('utf-8'), kdc_pub, signature):
            print("Signature VERIFIED")
            print(f"Master Key of Alice and KDC Ka = {Ka.decode('utf-8')}")
        else:
            print('Signature NOT VERIFIED')

        print("-------------------------------------------------------------------------------------")

        Ka_decode = Ka.decode('utf-8')

        # send Alice ID again
        msg = input('Press enter to send Alice ID for PHASE 2')
        client_socket.sendall(alice_id.encode('utf-8'))

        # decrypt the session key
        data_kdc = client_socket.recv(2048) # in bytes
        print("")
        print(f'RECEIVED')
        print('Decrypted Encrypted Session Key + Alice ID')
        print(data_kdc)
        print("")
        decr_data = AES_code.decrypt(data_kdc, Ka)
        sess_key, a_id = decr_data.decode('utf-8').split(delimiter)
        print(f"Session Key Kab = {sess_key}")
        print(f"Alice ID = {a_id}")


    finally:
        client_socket.close()


if __name__ == '__main__':
    run_client_A()    