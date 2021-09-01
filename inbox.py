from os import read
import PySimpleGUI as sg
from random import randint as rand


from messaging import *
import threading
import time
sg.theme("Black")

data = data

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
                if pubkey:

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
        
            send_an_email(from_address=user,
                        to_address=to_email,
                        subject=values['-EMAIL SUBJECT-'],
                        message_text=values['-EMAIL TEXT-'],
                        secret=encryption(pubkey, values['-SECRET TEXT-']),
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
    userinfo = json.load(open('.SecretService'))
    user = str()
    for i in userinfo:
        user = i
    mypubkey = userinfo[user]['pubKeyHex']
    selection = dict()
    header_list = ['From', 'Date', 'Public ECC/ECIES Ethereum Key']
    layout = [[sg.Table(values=data,
                        headings=header_list,
                        auto_size_columns=True,
                        justification='left',
                        num_rows=min(len(data), 5),
                        display_row_numbers=False,
                        font='Ubuntu',
                        size=(90,40),
                        key='table', enable_events=True,row_height=50,col_widths=50,right_click_menu=['&Right', ['Reply']]),sg.Image('logo.png')],
                [sg.Multiline(size = (130,40), key='output',background_color='black', text_color='green', font='Ubuntu')],
              [sg.Button("Check Email"), sg.Button('Compose Email/Key Exchange', key='Compose Email'), sg.Button('Close')]]

    window = sg.Window('SecretService Inbox - '+str(user), layout,auto_size_text=True,resizable=True)
    while True:
        event, values = window.read()
        if event in ('Close', None): break
        if event == "Check Email":
            threading.Thread(target=read_email_from_gmail,args=(window,data),daemon=True).start()
        if event == 'table':
            for element in values[event]:
                print(data)
                window['output'].update(data[element][3])
                selection = data[element]
        if event == 'Reply':
            if len(selection) == 0:
                reply(to_email='lancejames@unit221b.com',reply_message="RE: Welcome to SecretService\n\n")
            else:
                reply(to_email=selection[0],reply_message="\n\n\n\nOn "+selection[1]+" "+selection[0]+" wrote:\n"+selection[3])
        if event == "Compose Email":
            compose()
        



