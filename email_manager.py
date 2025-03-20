"""
Email management utilities for SecretService
"""
import imaplib
import smtplib
import email
from email.message import EmailMessage
from email.header import decode_header
import arrow
from typing import List, Optional, Dict, Any
from models import EmailMessage, MessageThread, ChaffeMessage
from crypto import CryptoManager, KeyManager
from config import settings
import pandas as pd
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class EmailManager:
    """Handles email operations for SecretService"""
    
    def __init__(self, email_address: str, password: str, service: str = 'gmail'):
        self.email = email_address
        self.password = password
        self.service = service.lower()
        self.crypto = CryptoManager()
        self.key_manager = KeyManager()
        
        # Load chaffe data
        try:
            self.chaffe_data = pd.read_csv(settings.CHAFFE_FILE, usecols=['Subject', 'content'])
            self.chaffe_data = self.chaffe_data.to_dict()
        except Exception as e:
            logger.error(f"Error loading chaffe data: {e}")
            raise RuntimeError("Failed to load chaffe data")

    def get_smtp_connection(self) -> smtplib.SMTP:
        """Get SMTP connection for sending emails
        
        Returns:
            smtplib.SMTP: SMTP connection object
        """
        try:
            smtp_host, smtp_port = settings.SMTP_SERVERS[self.service]
            server = smtplib.SMTP(host=smtp_host, port=smtp_port)
            server.starttls()
            server.login(user=self.email, password=self.password)
            return server
        except Exception as e:
            logger.error(f"Error connecting to SMTP server: {e}")
            raise RuntimeError("Failed to connect to SMTP server")

    def get_imap_connection(self) -> imaplib.IMAP4_SSL:
        """Get IMAP connection for receiving emails
        
        Returns:
            imaplib.IMAP4_SSL: IMAP connection object
        """
        try:
            imap_host, imap_port = settings.IMAP_SERVERS[self.service]
            mail = imaplib.IMAP4_SSL(imap_host, imap_port)
            mail.login(self.email, self.password)
            return mail
        except Exception as e:
            logger.error(f"Error connecting to IMAP server: {e}")
            raise RuntimeError("Failed to connect to IMAP server")

    def send_email(self, msg: EmailMessage) -> None:
        """Send an email
        
        Args:
            msg (EmailMessage): Email message to send
        """
        try:
            server = self.get_smtp_connection()
            
            email_msg = EmailMessage()
            
            # Set headers
            if msg.is_key_request:
                email_msg['X-Google-Message-State'] = self.crypto.encode_secret(msg.secret)
            else:
                email_msg['X-Gmail-Message-State'] = self.crypto.encode_secret(msg.secret)
            
            email_msg['From'] = msg.from_address
            email_msg['To'] = msg.to_address
            email_msg['Subject'] = msg.subject
            email_msg.set_content(msg.message_text)
            
            server.send_message(email_msg)
            server.close()
            
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            raise RuntimeError("Failed to send email")

    def get_random_chaffe(self) -> ChaffeMessage:
        """Get random chaffe (decoy) message
        
        Returns:
            ChaffeMessage: Random chaffe message
        """
        try:
            import random
            max_num = len(self.chaffe_data['Subject'])
            rand_num = random.randint(0, max_num - 1)
            return ChaffeMessage(
                subject=str(self.chaffe_data['Subject'][rand_num]),
                body=str(self.chaffe_data['content'][rand_num])
            )
        except Exception as e:
            logger.error(f"Error getting random chaffe: {e}")
            raise RuntimeError("Failed to get random chaffe")

    def fetch_recent_messages(self, days: int = 30) -> List[MessageThread]:
        """Fetch recent messages from inbox
        
        Args:
            days (int): Number of days of emails to fetch
            
        Returns:
            List[MessageThread]: List of message threads
        """
        try:
            mail = self.get_imap_connection()
            mail.select('inbox')
            
            # Calculate date for search
            date = (datetime.now() - timedelta(days=days)).strftime("%d-%b-%Y")
            search_criterion = f'SINCE "{date}"'
            
            # Search for messages
            _, messages = mail.search(None, search_criterion)
            message_threads = []
            
            for num in messages[0].split():
                _, msg_data = mail.fetch(num, '(RFC822)')
                
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        try:
                            msg = email.message_from_bytes(response_part[1])
                        except:
                            msg = email.message_from_string(str(response_part[1], 'utf-8'))
                            
                        # Process key exchange messages
                        if "X-Google-Message-State" in msg.keys():
                            header = decode_header(msg["X-Google-Message-State"])
                            secret = self.crypto.decode_secret(header[0][0])
                            from_email = msg['from']
                            if ">" in from_email:
                                from_email = from_email.split("<")[1].strip(">")
                            
                            # Save new contact key
                            self.key_manager.save_contact_key(from_email, secret)
                            
                        # Process encrypted messages
                        if "X-Gmail-Message-State" in msg.keys():
                            header = decode_header(msg["X-Gmail-Message-State"])
                            encrypted_data = self.crypto.decode_secret(header[0][0])
                            
                            from_email = msg['from']
                            if ">" in from_email:
                                from_email = from_email.split("<")[1].strip(">")
                                
                            # Get user credentials and decrypt
                            credentials = self.key_manager.load_user_credentials().get(self.email)
                            if credentials:
                                try:
                                    decrypted = self.crypto.decrypt_message(
                                        credentials.priv_key_hex,
                                        encrypted_data
                                    )
                                    
                                    thread = MessageThread(
                                        from_email=from_email,
                                        date=arrow.get(msg['Date']).datetime,
                                        pub_key=self.key_manager.get_contact_key(from_email),
                                        content=decrypted.plaintext
                                    )
                                    message_threads.append(thread)
                                except Exception as e:
                                    logger.warning(f"Failed to decrypt message from {from_email}: {e}")
                                    continue
            
            mail.close()
            mail.logout()
            
            return sorted(message_threads, key=lambda x: x.date, reverse=True)
            
        except Exception as e:
            logger.error(f"Error fetching messages: {e}")
            raise RuntimeError("Failed to fetch messages") 