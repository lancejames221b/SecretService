from imap_tools import MailBox, A
with MailBox('imap.mail.com').login('test@mail.com', 'password', 'INBOX') as mailbox:
    for msg in mailbox.fetch(A(all=True)):
        sender = msg.from_
        body = msg.text or msg.html