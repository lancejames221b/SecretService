from email import header
from os import read
import PySimpleGUI as sg
from random import randint as rand
from messaging import *
import threading
import time
sg.theme("Black")

data = data

def users_parser(email):
    multiple = []
    email = email.split(",")
    for mail in email:
        multiple.append(mail.strip())
    return multiple

def keyimage(string):
    from PIL import Image, ImageDraw, ImageFont
 
    img = Image.new('RGB', (100, 30), color = (73, 109, 137))
    fnt = ImageFont.truetype('CaviarDreams.ttf', 15)

    d = ImageDraw.Draw(img)
    d.text((10,10), string,  font=fnt,fill=(255,255,0))
 
    img.save('key.png')


def compose():
    decoy = getrandomchaffe()
    userinfo = json.load(open('.SecretService'))
    user = str()
    for i in userinfo:
        user = i
    mypubkey = userinfo[user]['pubKeyHex']
    
    service = 'gmail'
    layout_compose = [
              [sg.T('To:', size=(8,1)), sg.Input(key='-EMAIL TO-',font='Ubuntu'),sg.Button("Send Key",key='keyexchange')],
              [sg.T('Subject:', size=(8,1)), sg.Input(key='-EMAIL SUBJECT-', font='Ubuntu',default_text=decoy['subject'])],
              [sg.Text('Enter Decoy Message', font='Ubuntu')],
              [sg.Multiline(size=(150,20), key='-EMAIL TEXT-',background_color='white', text_color='black',font='Ubuntu',default_text=decoy['body'])],
              [sg.Text('Enter Secret Message', font='Ubuntu')],
              [sg.Multiline(size=(150,20), key='-SECRET TEXT-',background_color='black', text_color='green',font='Ubuntu')],
              [sg.Button('Send Email', key='Send'),  sg.Button('Exit', key = 'Exit')]
    ]
    window = sg.Window('SecretService - '+str(user), layout_compose,resizable=True)
    while True:  # Event Loop
        event, values = window.read()
        if event in (None, 'Exit'):
            window.close()
            break
        if event == 'keyexchange':
            if not values['-EMAIL TO-']:
                sg.popup('Forgot to put a user in the To field')
            else:
                pubkey = getkeys(values['-EMAIL TO-'])
                sg.popup_quick_message('Sending your Public Key... this will take a moment...', background_color='red')
            
                send_an_email(from_address=user,
                            to_address=values['-EMAIL TO-'],
                            subject=values['-EMAIL SUBJECT-'],
                            message_text=values['-EMAIL TEXT-'],
                            secret = mypubkey,
                            user=user,
                            password=userinfo[user]['password'],
                            service=service,keyrequest=True)
                window.close()
        if event == 'Send':
            pubkey = getkeys(values['-EMAIL TO-'])
            if not values['-EMAIL TO-']:
                sg.popup('Forgot to put a user in the To field')
            else:
                if pubkey and isinstance(pubkey, str):

                    sg.popup_quick_message('Sending your message... this will take a moment...', background_color='red')
                
                    send_an_email(from_address=user,
                                to_address=values['-EMAIL TO-'],
                                subject=values['-EMAIL SUBJECT-'],
                                message_text=values['-EMAIL TEXT-'],
                                secret=encryption(pubkey, values['-SECRET TEXT-']),
                                user=user,
                                password=userinfo[user]['password'],
                                service=service)
                    window.close()
                if pubkey and isinstance(pubkey, list):
                    values['-EMAIL TO-'] = users_parser(values['-EMAIL TO-'])
                    for index, keys in enumerate(pubkey):
                        

                        send_an_email(from_address=user,
                                    to_address=values['-EMAIL TO-'][index],
                                    subject=values['-EMAIL SUBJECT-'],
                                    message_text=values['-EMAIL TEXT-'],
                                    secret=encryption(keys, values['-SECRET TEXT-']),
                                    user=user,
                                    password=userinfo[user]['password'],
                                    service=service)
                    window.close()

                else:
                    sg.popup("Missing Pubkey for User. Click Send Your Key and Request Key From User.")
    window.close()              


def reply(to_email = None, reply_message = None):
    global data
    decoy = getrandomchaffe()
    userinfo = json.load(open('.SecretService'))
    user = str()
    for i in userinfo:
        user = i
    mypubkey = userinfo[user]['pubKeyHex']
    
    service = 'gmail'
    if isinstance(to_email, list): to_email = ','.join(to_email)
    layout_reply = [
              [sg.T('To:'+to_email, size=(50,1)),sg.Button("Send Key",key='keyexchange')],
              [sg.T('Subject:', size=(8,1)), sg.Input(key='-EMAIL SUBJECT-',font='Ubuntu', default_text=decoy['subject'])],
              [sg.Text('Enter Decoy Message', font='Ubuntu')],
              [sg.Multiline(size=(150,20), key='-EMAIL TEXT-',background_color='white', text_color='black',font='Ubuntu',default_text=decoy['body'])],
              [sg.Text('Enter Secret Message', font='Ubuntu')],
              [sg.Multiline(size=(150,20), key='-SECRET TEXT-',default_text=reply_message,background_color='black', text_color='green',font='Ubuntu')],
              [sg.Button('Send', key='Send'), sg.Button('Exit', key = 'Exit')]]
    window = sg.Window('SecretService - '+str(user), layout_reply,resizable=True)


    while True:  # Event Loop
        event, values = window.read()
        if event in (None, 'Exit'):
            window.close()
            break
    
        if event == 'Send':
            pubkey = getkeys(to_email)
            sg.popup_quick_message('Sending your message... this will take a moment...', background_color='red')
            if pubkey and isinstance(pubkey, str):
                            send_an_email(from_address=user,
                            to_address=to_email,
                            subject=values['-EMAIL SUBJECT-'],
                            message_text=values['-EMAIL TEXT-'],
                            secret=encryption(pubkey, values['-SECRET TEXT-']),
                            user=user,
                            password=userinfo[user]['password'],
                            service=service)
            window.close()
            if pubkey and isinstance(pubkey, list):
                for index, keys in enumerate(pubkey):
                    

                    send_an_email(from_address=user,
                                to_address=to_email[index],
                                subject=values['-EMAIL SUBJECT-'],
                                message_text=values['-EMAIL TEXT-'],
                                secret=encryption(keys, values['-SECRET TEXT-']),
                                user=user,
                                password=userinfo[user]['password'],
                                service=service)
                window.close()



        
        
        if event == 'keyexchange':
                pubkey = getkeys(to_email)
                sg.popup_quick_message('Sending your Public Key... this will take a moment...', background_color='red')
            
                send_an_email(from_address=user,
                            to_address=to_email,
                            subject=values['-EMAIL SUBJECT-'],
                            message_text=values['-EMAIL TEXT-'],
                            secret = mypubkey,
                            user=user,
                            password=userinfo[user]['password'],
                            service=service,keyrequest=True)
                window.close()      


def inbox():
    global data
    keylist = []
    THREAD_EVENT = '-THREAD-'
    QUERY = str()
    contactlist = []
    userinfo = json.load(open('.SecretService'))
    user = str()
    contacts = listpubkeys()
    for i in contacts:
        contactlist.append([i])
    for i in userinfo:
        user = i
    mypubkey = userinfo[user]['pubKeyHex']
    selection = dict()
    header_list = ['From', 'Date', 'Public ECC/ECIES Ethereum Key']
    options=[[sg.Frame('Contacts',[[sg.Table(values = contactlist,auto_size_columns=True,
                        headings = ['Authenticated Contact List'],
                        justification='left',
                        num_rows=min(37, 37),
                        display_row_numbers=False,
                        font='Ubuntu',
                        size=(50,30),key='contacts',enable_events=True,right_click_menu=['&Right', ['Email']])]]
    )]]
    layout = [[sg.Table(values=data,
                        headings=header_list,
                        auto_size_columns=True,
                        justification='left',
                        num_rows=min(len(data), 5),
                        display_row_numbers=False,
                        font='Ubuntu',
                        size=(90,40),
                        key='table', enable_events=True,row_height=50,col_widths=50,right_click_menu=['&Right', ['Reply']]),sg.Image('logo.png'), ],
                [sg.Multiline(size = (84,40), key='output',background_color='black', text_color='green', font='Ubuntu'),sg.Column(layout=options)],
              [sg.Button("Check Email"), sg.Button('Compose Email/Key Exchange', key='Compose Email'), sg.Button('My Public Key', key='MyKey'), sg.Button('Close'), sg.Text(key='status', size=(50,1), text_color='green', background_color='black')]]

    window = sg.Window('SecretService Inbox - '+str(user), layout,auto_size_text=True,resizable=True, return_keyboard_events=True)
    data = [['lancejames@unit221b.com', 'Wed 01 Sep 2021 02:09:28 PM EDT', '0x5b639f8907554525ab4e18e9c387433c9c4d8131eef89d983da19b6c7da9e17f87ce08e8667ccc9c985908f3ce3878dd9212f091cfa6f8bfe668730e0347ccc7', 'Welcome to SecretService Inbox\n\nFeel free to email me any time to exchange keys. Simply right-mouse on the message and click reply!']]

    threading.Thread(target=read_email_from_gmail,args=(window,data),daemon=True).start()
    
    while True:
        event, values = window.read()
        if event in ('Close', None): break
        if event == 'MyKey':
            
            window.TKroot.clipboard_clear()
            window.TKroot.clipboard_append(str(mypubkey))
            sg.PopupOK(str(mypubkey), title='Your Public Key Copied to Clipboard')
        if event == "Check Email":
            threading.Thread(target=read_email_from_gmail,args=(window,data),daemon=True).start()
        if event == 'table':
            window['output'].update('')
            for element in values[event]:
                try:
                    window['output'].update(data[element][3])
                    selection = data[element]
                except:
                    sg.popup_quick_message("Weird Error, click Check Email again and it will fix itself")
                
        if event == THREAD_EVENT:
            QUERY = str()
            keyverification = values[THREAD_EVENT]
            
            if keyverification[0] == 'NEWKEY' and keyverification[2] not in keylist:
                keyimage(keyverification[2])
                QUERY = sg.popup_yes_no(keyverification[1]+" has sent a key\n\n"+keyverification[2]+"\n\nIf you have verified the user's public key then hit OK.",title=keyverification[1]+' New Key Approval',keep_on_top=True,image='key.png',font='Ubuntu')
                if QUERY == "Yes": 
                    logkeys(keyverification[1], keyverification[2])
                    window['status'].update("Added New Public Key: "+keyverification[1])
                    keylist.append(keyverification[2])
            if keyverification[0] == 'KEYCHANGE' and keyverification[2] not in keylist:
                keyimage(keyverification[2])
                QUERY = sg.popup_ok_cancel(keyverification[1]+" PUBLIC KEY HAS CHANGED!!!\n"+keyverification[2]+"\nIf you have verified the user's new public key then hit OK, otherwise hit Cancel",title=keyverification[1]+' Updated Key Approval',keep_on_top=True,image='key.png', font='Ubuntu')
                if QUERY == "Yes": 
                    logkeys(keyverification[1], keyverification[2])
                    window['status'].update("Public Key Updated: "+keyverification[1])
                    keylist.append(keyverification[2])
  
            
            

        if event == 'Reply':
            if len(selection) == 0:
                reply(to_email='lancejames@unit221b.com',reply_message="RE: Welcome to SecretService\n\n")
            else:
                reply(to_email=selection[0],reply_message="\n\n\n\nOn "+selection[1]+" "+selection[0]+" wrote:\n"+selection[3])
        if event == "Compose Email":
            compose()
        if event == 'Email':
            contactlist = []
            contacts = listpubkeys()
            for i in contacts:
                contactlist.append([i])
            print(values['contacts'], len(values['contacts']))
            if len(values['contacts']) > 1:
                emails = []
                for element in values['contacts']:
                    emails.append(contactlist[element][0])
                reply(to_email = emails)
            else:
                for element in values['contacts']:
                    reply(to_email = contactlist[element][0])


            
        


        


