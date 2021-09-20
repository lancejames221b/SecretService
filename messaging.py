from datetime import date
from email.policy import default
from inspect import trace
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
from base64 import b64encode, b64decode
import binascii, json, os, sys
import imaplib
import email
import arrow
from email.header import decode_header
# used for sending the email
import smtplib  as smtp
# used to build the email
from email.message import EmailMessage
from random import randint
import pandas as pd
import itertools
import traceback

PATH = 'chaffe.csv'

chaffe = pd.read_csv(PATH,usecols=['Subject', 'content'])

chaffe = chaffe.to_dict()


def getrandomchaffe(chaffe=chaffe):
    maxnum = len(chaffe['Subject'])
    randnum = randint(0, maxnum)
    subject = chaffe['Subject'][randnum]
    body = chaffe['content'][randnum]
    return {'subject': str(subject), 'body': str(body)}

def parse_datetime(messagelist):
    for i in range(len(messagelist)):
        messagelist[i][1] = messagelist[i][1].format('ddd, D MMM YYYY h:mm:ss A')
    return messagelist

def listpubkeys():
    keys = json.load(open('.pubkeys'))
    return keys

data = [['lancejames@unit221b.com', 'Wed 01 Sep 2021 2:09:28 PM EDT', '0x5b639f8907554525ab4e18e9c387433c9c4d8131eef89d983da19b6c7da9e17f87ce08e8667ccc9c985908f3ce3878dd9212f091cfa6f8bfe668730e0347ccc7', 'Welcome to SecretService Inbox\n\nFeel free to email me any time to exchange keys. Simply right-mouse on the message and click reply!']]
def keygen(email, password, service):
    privKey = generate_eth_key()
    privKeyHex = privKey.to_hex()
    pubKeyHex = privKey.public_key.to_hex()
    return json.dump({email:{'pubKeyHex': pubKeyHex,'privKeyHex': privKeyHex, 'password': password, 'service':service}},open('.SecretService', 'w'),indent=4)

def encryption(pubKeyHex, plaintext, attach):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    encrypted = encrypt(pubKeyHex, plaintext)
    attaches = []
    for a in attach:
        if isinstance(a[0], str):
            a[0] = a[0].encode()
        if isinstance(a[1], str):
            a[1] = a[1].encode()
        attaches.append([encrypt(pubKeyHex, a[0]), encrypt(pubKeyHex, a[1])])
    attaches = json.dumps(attaches).encode()
    return {'ciphertext': str(binascii.hexlify(encrypted)).strip("b'"), 'attachments': str(binascii.hexlify(attaches)).strip("b'"), 'pubKeyHex': pubKeyHex}

def decryption(ciphertext, attaches, privKeyHex):
    ciphertext = ciphertext
    decrypted = decrypt(privKeyHex, binascii.unhexlify(ciphertext))
    decrpyted_attachments = []
    if attaches:
        attachments_list = json.loads(binascii.unhexlify(attaches).decode())
        print(attachments_list)
        for i in range(len(attachments_list)):
            attach = [decrypt(privKeyHex, attachments_list[i][0]), decrypt(privKeyHex, attachments_list[i][1])]
            attach[0] = attach[0].decode()
            attach[1] = attach[1].decode()
            decrpyted_attachments.append(attach)
    return {'plaintext': decrypted.decode(), 'attachments': decrpyted_attachments}

    
    

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
        return None
    server = smtp.SMTP(host=smtp_host, port=smtp_port)
    server.starttls()
    server.login(user=user, password=password)

    # create the email message headers and set the payload
    secret = json.dumps(secret)
    msg = EmailMessage()
    if not keyrequest: msg['X-Gmail-Message-State'] = b64encode(bytes(secret, 'utf-8')).decode()
    if keyrequest: msg['X-Google-Message-State'] = b64encode(bytes(secret, 'utf-8')).decode()
    msg['From'] = from_address.strip()
    msg['To'] = to_address.strip()
    msg['Subject'] = subject.strip()
    
    msg.set_payload(message_text)

    # open the email server and send the message
    server.send_message(msg)

    server.close()


def decode_message(message, user):
    incoming = json.loads(message)
    mykeys = json.load(open('.SecretService'))
    privkey = mykeys[user]['privKeyHex']
    plaintext = decryption(incoming['ciphertext'], incoming.get('attachments'), privkey)
    return plaintext
    
def logkeys(from_email, pubkey):
    keyset = dict()
    if os.path.isfile('.pubkeys'):
        keyset = json.load(open('.pubkeys'))
    keyset.update({from_email: pubkey.strip('''"''')})
    json.dump(keyset, open('.pubkeys', 'w'), indent=4)
    return keyset

def getkeys(user):
    multiple_user = []
    if os.path.isfile('.pubkeys'): 
        keyset = json.load(open('.pubkeys'))
    else: 
        return None
    try:
        if "," in user:
            user = user.strip().split(',')
            for users in user:
                multiple_user.append(keyset[users.strip()])
            print(multiple_user)
            return multiple_user
        return keyset[user]
    except Exception as e:
        traceback.print_exc()
        return None

def convert_datetime(email_date):
    if email_date[6] == ' ':
        email_date = email_date[:5] + '0' + email_date[5:]
    datetimeobj = None
    if email_date[-1].isalpha():
        datetimeobj = arrow.get(email_date, 'DD MMM YYYY HH:mm:ss ZZZ')
    else:
        datetimeobj = arrow.get(email_date, 'DD MMM YYYY HH:mm:ss Z')
    datetimeobj = datetimeobj.to('local')
    return datetimeobj
    
def read_email_from_gmail(window,messages = data, downloadkeys = False, SMTP_SERVER="imap.gmail.com", SMTP_PORT=993):
    #global data
    Q = False
    userpubkeys = dict()
    userinfo = json.load(open('.SecretService'))
    user = str()
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

        data = mail.search(None, 'SINCE "20-Aug-2021"')
        mail_ids = data[1]
        id_list = mail_ids[0].split()   
        first_email_id = int(id_list[0])
        latest_email_id = int(id_list[-1])
        window['status'].update("Retrieving Public Keys, this can take some time...")
    #   window['table'].update("")

        for i in range(latest_email_id,first_email_id, -1):
            data = mail.fetch(str(i), '(RFC822)' )
            for response_part in data:
                arr = response_part[0]
                if isinstance(arr, tuple):
                    msg = email.message_from_string(str(arr[1],'utf-8"'))
                    if "X-Google-Message-State" in msg.keys():
                        email_subject = msg['subject']
                        header = decode_header(msg['X-Google-Message-State'])
                        SecretServiceKey = [(b64decode(header[0][0] + b'==').hex(), header[0][1])]
                        #print(SecretService, 'Debug', SecretService[0][1]) 
                       # SecretService = bytes.fromhex(SecretService[0][0])
                        
                        email_from = msg['from']
                        if ">" in email_from: email_from = email_from.split("<")[1].strip(">")
                        if SecretServiceKey[0][1]:
                            keyverify = listpubkeys()
                            if email_from not in keyverify.keys():
                                window.write_event_value('-THREAD-',['NEWKEY', email_from, bytes.fromhex(SecretServiceKey[0][0]).decode(errors='ignore').strip('''"''')],)

                                
                            if email_from in keyverify.keys() and bytes.fromhex(SecretServiceKey[0][0]).decode(errors='ignore').strip('''"''') not in keyverify[email_from]:
                                window.write_event_value('-THREAD-',['KEYCHANGE', email_from, bytes.fromhex(SecretServiceKey[0][0]).decode(errors='ignore').strip('''"''')],)
                                    
                        


                            
                        else:
                            print("Else PK")
                            try:
                                keyverify = listpubkeys()
                                if email_from not in keyverify.keys():
                                    window.write_event_value('-THREAD-',['NEWKEY', email_from, str(bytes.fromhex(SecretServiceKey[0][0]).decode(errors='ignore')).strip('''"''')])
                                    
                                if email_from in keyverify.keys() and str(bytes.fromhex(SecretServiceKey[0][0]).decode(errors='ignore')).strip('''"''') not in keyverify[email_from]:
                                    window.write_event_value('-THREAD-',['KEYCHANGE',email_from, str(bytes.fromhex(SecretServiceKey[0][0]).decode(errors='ignore')).strip('''"''')])
                                    
                            except:
                                return
                            
                    if "X-Gmail-Message-State" in msg.keys():
                        header = decode_header(msg['X-Gmail-Message-State'])
                        SecretService = [(b64decode(header[0][0] + b'==').hex(), header[0][1])]
                        #print(SecretService, 'Debug', SecretService[0][1]) 
                        # SecretService = bytes.fromhex(SecretService[0][0])
                        
                        
                        
                        email_from = msg['from']
                        if ">" in email_from: email_from = email_from.split("<")[1].strip(">")
                        EncryptedMessage = bytes.fromhex(SecretService[0][0]).decode(errors='ignore')
                        try:
                            plaintext = decode_message(EncryptedMessage, user)
                        except ValueError as e:
                            continue
                        if plaintext:
                            window['status'].update("Retrieving Email: "+str(email_from))
                            
                            #window['-MESSAGES-'].print("Date :", msg['Date'])
                            #   window['-MESSAGES-'].print('From: ', email_from)
                            #   window['-MESSAGES-'].print("\n---MESSAGE BEGIN---\n\n",plaintext['plaintext'])
                            #  window['-MESSAGES-'].print("\n---MESSAGE END---\n")
                            try:
                                if len(messages) > 0 and '''Wed, 01 Sep 2021 2:09:28 PM''' in messages[0]:
                                    messages.pop(0)
                                for i in range(len(messages)):
                                    if type(messages[i][1]) == type(''):
                                        messages[i][1] = arrow.get(messages[i][1], 'ddd, D MMM YYYY h:mm:ss A').replace(tzinfo='local')
                                messages.append([email_from, convert_datetime(msg['Date']), userpubkeys[email_from],plaintext['plaintext']])
                                messages.sort(key=lambda x: int(x[1].timestamp()), reverse=True)
                                newmessages = parse_datetime(messages)
                                
                                window['table'].update(values=newmessages)
                                window['table'].update(num_rows=min(len(newmessages), 5))
                                window.write_event_value('messages_update', newmessages)
                            except Exception as e:
                                print(e)
                                Q = True

                    
                        else:
                            print("Else, Messages")
                            EncryptedMessage = bytes.fromhex(SecretService[0][0]).decode()
                            try:
                                plaintext = decode_message(EncryptedMessage, user)
                            except ValueError as e:
                                continue
                            if plaintext:
                                # window['-MESSAGES-'].print("Date :", msg['Date'])
                                # window['-MESSAGES-'].print('From: ', email_from)
                                # window['-MESSAGES-'].print("\n---MESSAGE BEGIN---\n\n", plaintext['plaintext'])
                                # window['-MESSAGES-'].print("\n---MESSAGE END---\n")
                                try:
                                    if len(messages) > 0 and '''Wed, 01 Sep 2021 2:09:28 PM''' in messages[0]:
                                        messages.pop(0)
                                    for i in range(len(messages)):
                                        if type(messages[i][1]) == type(''):
                                            messages[i][1] = arrow.get(messages[i][1], 'ddd, D MMM YYYY h:mm:ss A').replace(tzinfo='local')
                                    messages.append([email_from, convert_datetime(msg['Date']), userpubkeys[email_from],plaintext['plaintext']])
                                    messages.sort(key=lambda x: int(x[1].timestamp()), reverse=True)
                                    newmessages = parse_datetime(messages)

                                    window['table'].update(values=newmessages)
                                    window['table'].update(num_rows=min(len(newmessages), 5))
                                    window.write_event_value('messages_update', newmessages)
                                except Exception as e:
                                    Q = True
                    
        contactlist = []
        contacts = listpubkeys()
        for i in contacts:
            contactlist.append([i])
        window['contacts'].update(values=contactlist)
        mail.close()
        window['status'].update("")
        if Q: 
            read_email_from_gmail(window, messages = [['lancejames@unit221b.com', 'Wed 01 Sep 2021 2:09:28 PM EDT', '0x5b639f8907554525ab4e18e9c387433c9c4d8131eef89d983da19b6c7da9e17f87ce08e8667ccc9c985908f3ce3878dd9212f091cfa6f8bfe668730e0347ccc7', 'Welcome to SecretService Inbox\n\nFeel free to email me any time to exchange keys. Simply right-mouse on the message and click reply!']])
        

        
        
        
        return 
    except Exception as e:
        print(e)
        traceback.print_exc()
        
        
        contactlist = []
        contacts = listpubkeys()
        for i in contacts:
            contactlist.append([i])
        window['contacts'].update(values=contactlist)
        mail.close()
        window['status'].update("")
        if Q: 
            read_email_from_gmail(window, messages = [['lancejames@unit221b.com', 'Wed 01 Sep 2021 2:09:28 PM EDT', '0x5b639f8907554525ab4e18e9c387433c9c4d8131eef89d983da19b6c7da9e17f87ce08e8667ccc9c985908f3ce3878dd9212f091cfa6f8bfe668730e0347ccc7', 'Welcome to SecretService Inbox\n\nFeel free to email me any time to exchange keys. Simply right-mouse on the message and click reply!']])
       
