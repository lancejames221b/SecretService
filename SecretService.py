import PySimpleGUI as sg
import json
import os, sys
import webbrowser
import threading
# used for sending the email
# used to build the email
from inbox import *
from messaging import *







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

