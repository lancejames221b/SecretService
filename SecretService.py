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
        inbox()
    else:
        sg.popup_quick_message("Please fill in all the values.", background_color='red')
        window.close()
        Register()



    
                

    
def main():
    if os.path.isfile(".SecretService"):
        inbox()
    else:
        Register()


main()

