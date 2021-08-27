from email.policy import default
import PySimpleGUI as sg
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
import binascii, json
import os, sys
import webbrowser
import time
import imaplib
import email
from base64 import b64decode, b64encode
from email.header import decode_header
import threading
import traceback
from Crypto.Cipher import Salsa20
import hashlib



# used for sending the email
import smtplib  as smtp
# used to build the email
from email.message import EmailMessage

def keygen(email, password, service):
    privKey = generate_eth_key()
    privKeyHex = privKey.to_hex()
    pubKeyHex = privKey.public_key.to_hex()
    return json.dump({email:{'pubKeyHex': pubKeyHex,'privKeyHex': privKeyHex, 'password': password, 'service':service}},open('.SecretService', 'w'),indent=4)

def encryption(pubKeyHex, plaintext):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    encrypted = encrypt(pubKeyHex, plaintext)
    return {'ciphertext': str(binascii.hexlify(encrypted)).strip("b'"), 'pubKeyHex': pubKeyHex}

def decryption(ciphertext, privKeyHex):
    decrypted = decrypt(privKeyHex, binascii.unhexlify(ciphertext)) 
    return {'plaintext': decrypted.decode()}

    
    

# create and send email
def send_an_email(from_address, to_address, subject, message_text, secret, pubkey, user, password,service='gmail',keyrequest = False):
    # SMTP Servers for popular free services... add your own if needed. Format is: address, port
    google_smtp_server = 'smtp.gmail.com', 587
    microsoft_smtp_server = 'smtp.office365.com', 587
    yahoo_smtp_server = 'smtp.mail.yahoo.com', 587  # or port 465

    # open the email server connection
    if 'gmail' in service:
        smtp_host, smtp_port = google_smtp_server
    elif 'microsoft' in service:
        smtp_host, smtp_port = microsoft_smtp_server
    elif 'yahoo' in service:
        smtp_host, smtp_port = yahoo_smtp_server
    else:
        sg.popup('Username does not contain a supported email provider')
        return
    server = smtp.SMTP(host=smtp_host, port=smtp_port)
    server.starttls()
    server.login(user=user, password=password)

    # create the email message headers and set the payload
    secret = json.dumps(secret)
    msg = EmailMessage()
    if not keyrequest: msg['X-Gmail-Message-State'] = bytes(secret,'utf-8').hex()
    if keyrequest: msg['X-Google-Message-State'] = bytes(secret,'utf-8').hex()
    msg['From'] = from_address
    msg['To'] = to_address
    msg['Subject'] = subject
    
    msg.set_payload(message_text)

    # open the email server and send the message
    server.send_message(msg)

    server.close()


def decode_message(message, user):
    incoming = json.loads(message)
    mykeys = json.load(open('.SecretService'))
    privkey = mykeys[user]['privKeyHex']
    plaintext = decryption(incoming['ciphertext'], privkey)

    
    
    return plaintext
    
def logkeys(from_email, pubkey):
    keyset = dict()
    if os.path.isfile('.pubkeys'):
        keyset = json.load(open('.pubkeys'))
        
    keyset.update({from_email: pubkey.strip('''"''')})
    json.dump(keyset, open('.pubkeys', 'w'))
    return keyset

def getkeys(user):
    if os.path.isfile('.pubkeys'): 
        keyset = json.load(open('.pubkeys'))
    else: 
        return None
    try:
        return keyset[user]
    except Exception as e:
        
        return None
    
def read_email_from_gmail(window,downloadkeys = False, SMTP_SERVER="imap.gmail.com", SMTP_PORT=993):
    userpubkeys = dict()
    userinfo = json.load(open('.SecretService'))
    for x in userinfo:
        user = x
    if os.path.isfile('.pubkeys'):
        userpubkeys = json.load(open('.pubkeys'))
    for i in userinfo:
        FROM_EMAIL = i

    FROM_PWD = userinfo[FROM_EMAIL]['password']
    try:
        mail = imaplib.IMAP4_SSL(SMTP_SERVER)
        mail.login(FROM_EMAIL,FROM_PWD)
        mail.select('inbox')

        data = mail.search(None, 'ALL')
        mail_ids = data[1]
        id_list = mail_ids[0].split()   
        first_email_id = int(id_list[0])
        latest_email_id = int(id_list[-1])

        for i in range(latest_email_id,first_email_id, -1):
            data = mail.fetch(str(i), '(RFC822)' )
            for response_part in data:
                arr = response_part[0]
                if isinstance(arr, tuple):
                    msg = email.message_from_string(str(arr[1],'utf-8'))
                    if "X-Google-Message-State" in msg.keys():
                        email_subject = msg['subject']
                        SecretServiceKey = decode_header(msg['X-Google-Message-State'])
                        #print(SecretService, 'Debug', SecretService[0][1]) 
                       # SecretService = bytes.fromhex(SecretService[0][0])
                        
                
                        email_from = msg['from']
                        if SecretServiceKey[0][1]:
                            logkeys(email_from, bytes.fromhex(SecretServiceKey[0][0].decode()).decode())
                            #sg.popup_quick_message('Received Key for '+str(email_from), background_color='red', non_blocking=True)

                            
                        else:
                            logkeys(email_from,str(bytes.fromhex(SecretServiceKey[0][0]).decode()))
                            #sg.popup_quick_message('Received Key for '+str(email_from), background_color='red', non_blocking=True)

                    if "X-Gmail-Message-State" in msg.keys():
                        email_subject = msg['subject']
                        SecretService = decode_header(msg['X-Gmail-Message-State'])
                        #print(SecretService, 'Debug', SecretService[0][1]) 
                       # SecretService = bytes.fromhex(SecretService[0][0])
                        
                        

                        
                        email_from = msg['from']
                        
                        if SecretService[0][1]:
                            EncryptedMessage = bytes.fromhex(SecretService[0][0].decode()).decode()
                            plaintext = decode_message(EncryptedMessage, user)
                            if plaintext:
                                window['-MESSAGES-'].print("Date :", msg['Date'])
                                window['-MESSAGES-'].print('From: ', email_from)
                                window['-MESSAGES-'].print('Subject: ' + email_subject)
                                window['-MESSAGES-'].print("\n---MESSAGE BEGIN---\n\n",plaintext['plaintext'])
                                window['-MESSAGES-'].print("\n---MESSAGE END---\n")
                            
                        else:
                            EncryptedMessage = bytes.fromhex(SecretService[0][0]).decode()
                            plaintext = decode_message(EncryptedMessage, user)
                            if plaintext:
                                window['-MESSAGES-'].print("Date :", msg['Date'])
                                window['-MESSAGES-'].print('From: ', email_from)
                                window['-MESSAGES-'].print('Subject: ' + email_subject)
                                window['-MESSAGES-'].print("\n---MESSAGE BEGIN---\n\n", plaintext['plaintext'])
                                window['-MESSAGES-'].print("\n---MESSAGE END---\n")
                    else:
                        continue
        return
    except Exception as e:
        
        return

def listpubkeys(window):
    keys = json.load(open('.pubkeys'))
    window['-MESSAGES-'].update(json.dumps(keys, indent=4))

def Register():
    sg.change_look_and_feel('Black')
    url = 'https://myaccount.google.com/apppasswords'
    webbrowser.open(url)
    layout = [
    [sg.Text('Please make an app password in your email security settings for the password below')],
    [sg.Text('Email', size=(15, 1)), sg.InputText(key='-REG EMAIL-')],
    [sg.Text('App Password', size=(15, 1)), sg.InputText(key='-PASSWORD-',password_char="*")],
    [sg.Submit(), sg.Cancel(key = 'Cancel')]
    ]

    window = sg.Window('Register Email Account', layout)
    event, values = window.read()
    if event == 'Cancel':
        window.close()
        sys.exit()
        return
    if values['-REG EMAIL-'] and values['-PASSWORD-']:
        keygen(values['-REG EMAIL-'],values['-PASSWORD-'],service='gmail')
        window.close()
        SecretService()
    else:
        sg.popup_quick_message("Please fill in all the values.", background_color='red')
        window.close()
        Register()


def SecretService():
    userinfo = json.load(open('.SecretService'))
    user = str()
    for i in userinfo:
        user = i
    mypubkey = userinfo[user]['pubKeyHex']
    
    service = 'gmail'
    sg.change_look_and_feel('Black')
    tab1_layout = [
              [sg.T('To:', size=(8,1)), sg.Input(key='-EMAIL TO-')],
              [sg.T('Subject:', size=(8,1)), sg.Input(key='-EMAIL SUBJECT-')],
              [sg.Text('Enter Decoy Message', font='Default 18')],
              [sg.Multiline(size=(150,20), key='-EMAIL TEXT-',expand_x=True, expand_y=True)],
              [sg.Text('Enter Secret Message', font='Default 18')],
              [sg.Multiline(size=(150,20), key='-SECRET TEXT-',expand_x=True, expand_y=True)],
              [sg.Button('Send'), sg.Button('Exit', key = 'Exit')]]
    tab2_layout = [
              
              [sg.Multiline(size=(150,40), key='-MESSAGES-',expand_x=True, expand_y=True)],
              [sg.Button('Check Mail',key='refresh'), sg.Button("List Public Keys", key='listkeys'), sg.Button('Exit', key='Exit2')]]
    tab3_layout = [
              [sg.T('To:', size=(8,1)), sg.Input(key='-EMAIL TO2-')],
              [sg.T('Subject:', size=(8,1)), sg.Input(key='-EMAIL SUBJECT2-',default_text="Let's Catch Up Tonight")],
              [sg.Text('Enter Decoy Message', font='Default 18')],
              [sg.Multiline(default_text = "I'll call you later today", size=(150,20), key='-EMAIL TEXT2-',expand_x=True, expand_y=True)],
              [sg.Button('Send Key'),  sg.Button('Exit', key='Exit1')]]
    layout = [[sg.TabGroup([[sg.Tab('Exchange Keys', tab3_layout), sg.Tab('Sending', tab1_layout), sg.Tab('Receiving', tab2_layout)]])]]    
    window = sg.Window('SecretService - '+str(user), layout,resizable=True).Finalize()

    while True:  # Event Loop
        event, values = window.read()
        if event in (None, 'Exit', 'Exit2', 'Exit1'):
            window.close()
            break
        if event == 'listkeys':
            t1 = threading.Thread(target=listpubkeys, args=(window,),daemon=True)
            t1.start()
        if event == 'gmail':
            service = 'gmail'
        if event == 'yahoo':
            service = 'yahoo'
        if event == 'live' or event == 'hotmail':
            service = 'microsoft'
        if event == ('refresh'):
            window['-MESSAGES-'].update("")
            t2 = threading.Thread(target=read_email_from_gmail, args=(window,), daemon=True)
            t2.start()
        if event == 'Send Key':
            pubkey = getkeys(values['-EMAIL TO2-'])
            if not values['-EMAIL TO2-']:
                sg.popup('Forgot to put a user in the To field')
            else:

                sg.popup_quick_message('Sending your Public Key... this will take a moment...', background_color='red')
            
                send_an_email(from_address=user,
                            to_address=values['-EMAIL TO2-'],
                            subject=values['-EMAIL SUBJECT2-'],
                            message_text=values['-EMAIL TEXT2-'],
                            secret=mypubkey,
                            pubkey = mypubkey,
                            user=user,
                            password=userinfo[user]['password'],
                            service=service,keyrequest=True)

                
                
        if event == 'Send':
            pubkey = getkeys(values['-EMAIL TO-'])
            if not values['-EMAIL TO-']:
                sg.popup('Forgot to put a user in the To field')
            else:
                if pubkey:

                    sg.popup_quick_message('Sending your message... this will take a moment...', background_color='red')
                
                    send_an_email(from_address=user,
                                to_address=values['-EMAIL TO-'],
                                subject=values['-EMAIL SUBJECT-'],
                                message_text=values['-EMAIL TEXT-'],
                                secret=encryption(pubkey, values['-SECRET TEXT-']),
                                pubkey = mypubkey,
                                user=user,
                                password=userinfo[user]['password'],
                                service=service)
                else:
                    sg.popup("Missing Pubkey for User. Go to Exchange Keys Tab")
    window.close()              
                

    
def main():
    if os.path.isfile(".SecretService"):
        SecretService()
    else:
        Register()


main()

