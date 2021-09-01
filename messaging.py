from email.policy import default
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
import binascii, json, os, sys
import imaplib
import email
from email.header import decode_header
# used for sending the email
import smtplib  as smtp
# used to build the email
from email.message import EmailMessage
from random import randint
import pandas as pd

PATH = 'chaffe.csv'

chaffe = pd.read_csv(PATH,usecols=['Subject', 'content'])

chaffe = chaffe.to_dict()


def getrandomchaffe(chaffe=chaffe):
    maxnum = len(chaffe['Subject'])
    randnum = randint(0, maxnum)
    subject = chaffe['Subject'][randnum]
    body = chaffe['content'][randnum]
    return {'subject': str(subject), 'body': str(body)}



def listpubkeys(window):
    keys = json.load(open('.pubkeys'))
    window['-MESSAGES-'].update(json.dumps(keys, indent=4))

data = [['lancejames@unit221b.com', 'Wed 01 Sep 2021 02:09:28 PM EDT', '0x5b639f8907554525ab4e18e9c387433c9c4d8131eef89d983da19b6c7da9e17f87ce08e8667ccc9c985908f3ce3878dd9212f091cfa6f8bfe668730e0347ccc7', 'Welcome to SecretService Inbox\n\nFeel free to email me any time to exchange keys. Simply right-mouse on the message and click reply!']]
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
def send_an_email(from_address, to_address, subject, message_text, secret, user, password,service='gmail',keyrequest = False,chaffe=True):
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
    
def read_email_from_gmail(window,messages = data, downloadkeys = False, SMTP_SERVER="imap.gmail.com", SMTP_PORT=993):
    #global data
    messages.pop()
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
                        if ">" in email_from: email_from = email_from.split("<")[1].strip(">")
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
                        if ">" in email_from: email_from = email_from.split("<")[1].strip(">")
                        EncryptedMessage = bytes.fromhex(SecretService[0][0].decode()).decode()
                        plaintext = decode_message(EncryptedMessage, user)
                        if plaintext:
                            
                            #window['-MESSAGES-'].print("Date :", msg['Date'])
                            #   window['-MESSAGES-'].print('From: ', email_from)
                            #   window['-MESSAGES-'].print("\n---MESSAGE BEGIN---\n\n",plaintext['plaintext'])
                            #  window['-MESSAGES-'].print("\n---MESSAGE END---\n")
                            messages.append([email_from, msg['Date'], userpubkeys[email_from],plaintext['plaintext']])
                            window['table'].update(values=messages)
                            window['table'].update(num_rows=min(len(messages), 5))

                    
                        else:
                            EncryptedMessage = bytes.fromhex(SecretService[0][0]).decode()
                            plaintext = decode_message(EncryptedMessage, user)
                            if plaintext:
                               # window['-MESSAGES-'].print("Date :", msg['Date'])
                               # window['-MESSAGES-'].print('From: ', email_from)
                               # window['-MESSAGES-'].print("\n---MESSAGE BEGIN---\n\n", plaintext['plaintext'])
                               # window['-MESSAGES-'].print("\n---MESSAGE END---\n")
                                messages.append([email_from, msg['Date'], userpubkeys[email_from],plaintext['plaintext']])
                                window['table'].update(values=messages)
                                window['table'].update(num_rows=min(len(messages), 5))

                                
       
        return 
    except Exception as e:
        print(e)

        return