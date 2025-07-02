
@mcp.tool()
def gmail_read_message(message_id: str) -> str:
    """Extract readable text body from a Gmail message"""
    try:
        message = gmail_service.users().messages().get(
            userId='me', id=message_id, format='full'
        ).execute()

        payload = message.get('payload', {})
        body = extract_plain_text_from_payload(payload)

        if not body:
            return "No plain text body found in the message."

        return body

    except HttpError as e:
        return json.dumps({'error': str(e)}, indent=2)

def extract_plain_text_from_payload(payload):
    """Recursively find plain text body in Gmail MIME payload"""
    if payload.get('mimeType') == 'text/plain':
        data = payload.get('body', {}).get('data')
        if data:
            return decode_base64(data)

    for part in payload.get('parts', []):
        result = extract_plain_text_from_payload(part)
        if result:
            return result

    return None

def decode_base64(data):
    try:
        return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
    except Exception as e:
        return f"[Decode error: {e}]"
    
@mcp.tool()
def gmail_list_messages(max_results: int = 10, query: Optional[str] = None) -> str:
    """List recent emails with optional query filter"""
    try:
        params = {'userId': 'me', 'maxResults': max_results}
        if query:
            params['q'] = query
        response = gmail_service.users().messages().list(**params).execute()
        messages = response.get('messages', [])
        
        if not messages:
            return "No messages found."
        
        # Get basic info for each message
        message_list = []
        for msg in messages:
            try:
                full_msg = gmail_service.users().messages().get(
                    userId='me', id=msg['id'], format='metadata',
                    metadataHeaders=['From', 'Subject', 'Date']
                ).execute()
                
                headers = full_msg.get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                from_addr = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown Date')
                
                message_list.append({
                    'id': msg['id'],
                    'subject': subject,
                    'from': from_addr,
                    'date': date
                })
            except Exception as e:
                message_list.append({
                    'id': msg['id'],
                    'error': f'Error fetching message: {str(e)}'
                })
        
        return json.dumps(message_list, indent=2)
    
    except HttpError as e:
        return json.dumps({'error': str(e)}, indent=2)

@mcp.tool()
def gmail_get_message(message_id: str) -> str:
    """Get full email by ID"""
    try:
        message = gmail_service.users().messages().get(
            userId='me', id=message_id, format='full'
        ).execute()
        return json.dumps(message, indent=2)
    except HttpError as e:
        return json.dumps({'error': str(e)}, indent=2)
# Add this tool to your mcp_toolkit.py file

import email
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from datetime import datetime, timedelta

@mcp.tool()
def gmail_read_attachments(
    sender: Optional[str] = None,
    recipient: Optional[str] = None,
    subject_contains: Optional[str] = None,
    email_id: Optional[str] = None,
    max_results: int = 10,
    days_back: int = 30,
    save_attachments: bool = False,
    attachment_save_path: str = "./downloads/"
) -> str:
    """
    Read and extract attachments from Gmail messages based on various search criteria
    
    Args:
        sender: Filter by sender email address (e.g., "john@example.com")
        recipient: Filter by recipient email address 
        subject_contains: Filter by text contained in subject line
        email_id: Specific Gmail message ID to read attachments from
        max_results: Maximum number of emails to process (default: 10)
        days_back: How many days back to search (default: 30)
        save_attachments: Whether to save attachments to disk (default: False)
        attachment_save_path: Path to save attachments if save_attachments=True
    """
    try:
        # If specific email ID is provided, process only that email
        if email_id:
            return _process_single_email_attachments(email_id, save_attachments, attachment_save_path)
        
        # Build Gmail search query
        query_parts = []
        
        # Add sender filter
        if sender:
            query_parts.append(f"from:{sender}")
        
        # Add recipient filter  
        if recipient:
            query_parts.append(f"to:{recipient}")
        
        # Add subject filter
        if subject_contains:
            query_parts.append(f'subject:"{subject_contains}"')
        
        # Add date filter
        date_filter = datetime.now() - timedelta(days=days_back)
        query_parts.append(f"after:{date_filter.strftime('%Y/%m/%d')}")
        
        # Add attachment filter
        query_parts.append("has:attachment")
        
        # Combine query parts
        search_query = " ".join(query_parts)
        
        print(f"Gmail search query: {search_query}")
        
        # Search for messages
        results = gmail_service.users().messages().list(
            userId='me',
            q=search_query,
            maxResults=max_results
        ).execute()
        
        messages = results.get('messages', [])
        
        if not messages:
            return f"No emails found matching the criteria:\n" + \
                   f"- Sender: {sender or 'Any'}\n" + \
                   f"- Recipient: {recipient or 'Any'}\n" + \
                   f"- Subject contains: {subject_contains or 'Any'}\n" + \
                   f"- Days back: {days_back}\n"
        
        all_attachments = []
        processed_emails = 0
        
        # Process each message
        for message in messages:
            try:
                attachments = _extract_attachments_from_message(
                    message['id'], 
                    save_attachments, 
                    attachment_save_path
                )
                if attachments:
                    all_attachments.extend(attachments)
                processed_emails += 1
            except Exception as e:
                print(f"Error processing message {message['id']}: {str(e)}")
                continue
        
        # Format response
        if not all_attachments:
            return f"Processed {processed_emails} emails but found no attachments."
        
        response = f"Found {len(all_attachments)} attachments from {processed_emails} emails:\n\n"
        
        # Group by email
        emails_with_attachments = {}
        for attachment in all_attachments:
            email_key = f"{attachment['email_subject']} (from: {attachment['sender']})"
            if email_key not in emails_with_attachments:
                emails_with_attachments[email_key] = []
            emails_with_attachments[email_key].append(attachment)
        
        # Format output
        for email_info, attachments in emails_with_attachments.items():
            response += f"📧 {email_info}\n"
            response += f"   Date: {attachments[0]['email_date']}\n"
            response += f"   Message ID: {attachments[0]['message_id']}\n"
            response += f"   Attachments ({len(attachments)}):\n"
            
            for i, attachment in enumerate(attachments, 1):
                response += f"   {i}. {attachment['filename']} ({attachment['size']} bytes)\n"
                response += f"      Type: {attachment['mime_type']}\n"
                if attachment.get('saved_path'):
                    response += f"      Saved to: {attachment['saved_path']}\n"
                if attachment.get('content_preview'):
                    response += f"      Preview: {attachment['content_preview'][:100]}...\n"
                response += "\n"
            
            response += "-" * 50 + "\n"
        
        return response
        
    except HttpError as e:
        return f"Gmail API error: {str(e)}"
    except Exception as e:
        return f"Error reading email attachments: {str(e)}"


def _process_single_email_attachments(email_id: str, save_attachments: bool, save_path: str) -> str:
    """Process attachments from a single email by ID"""
    try:
        attachments = _extract_attachments_from_message(email_id, save_attachments, save_path)
        
        if not attachments:
            return f"No attachments found in email ID: {email_id}"
        
        response = f"Found {len(attachments)} attachments in email:\n\n"
        response += f"📧 {attachments[0]['email_subject']}\n"
        response += f"From: {attachments[0]['sender']}\n"
        response += f"Date: {attachments[0]['email_date']}\n"
        response += f"Message ID: {email_id}\n\n"
        response += "Attachments:\n"
        
        for i, attachment in enumerate(attachments, 1):
            response += f"{i}. {attachment['filename']} ({attachment['size']} bytes)\n"
            response += f"   Type: {attachment['mime_type']}\n"
            if attachment.get('saved_path'):
                response += f"   Saved to: {attachment['saved_path']}\n"
            if attachment.get('content_preview'):
                response += f"   Preview: {attachment['content_preview'][:100]}...\n"
            response += "\n"
        
        return response
        
    except Exception as e:
        return f"Error processing email {email_id}: {str(e)}"


def _extract_attachments_from_message(message_id: str, save_attachments: bool, save_path: str) -> List[Dict]:
    """Extract attachments from a Gmail message"""
    try:
        # Get full message
        message = gmail_service.users().messages().get(
            userId='me', 
            id=message_id,
            format='full'
        ).execute()
        
        # Extract email metadata
        headers = message['payload'].get('headers', [])
        email_subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
        email_date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown Date')
        
        attachments = []
        
        # Process message parts
        def process_parts(parts, attachments_list):
            for part in parts:
                # Check if part has nested parts
                if 'parts' in part:
                    process_parts(part['parts'], attachments_list)
                    continue
                
                # Check if part is an attachment
                if part.get('filename') and part['body'].get('attachmentId'):
                    attachment_info = {
                        'filename': part['filename'],
                        'mime_type': part['mimeType'],
                        'size': part['body'].get('size', 0),
                        'attachment_id': part['body']['attachmentId'],
                        'message_id': message_id,
                        'email_subject': email_subject,
                        'sender': sender,
                        'email_date': email_date
                    }
                    
                    # Download attachment data
                    try:
                        attachment_data = gmail_service.users().messages().attachments().get(
                            userId='me',
                            messageId=message_id,
                            id=part['body']['attachmentId']
                        ).execute()
                        
                        # Decode attachment data
                        file_data = base64.urlsafe_b64decode(attachment_data['data'])
                        attachment_info['data'] = file_data
                        
                        # Add content preview for text files
                        if part['mimeType'].startswith('text/'):
                            try:
                                attachment_info['content_preview'] = file_data.decode('utf-8')
                            except:
                                attachment_info['content_preview'] = "Binary content"
                        
                        # Save to disk if requested
                        if save_attachments:
                            # Create save directory if it doesn't exist
                            os.makedirs(save_path, exist_ok=True)
                            
                            # Generate unique filename to avoid conflicts
                            base_filename = part['filename']
                            save_filename = base_filename
                            counter = 1
                            
                            while os.path.exists(os.path.join(save_path, save_filename)):
                                name, ext = os.path.splitext(base_filename)
                                save_filename = f"{name}_{counter}{ext}"
                                counter += 1
                            
                            full_save_path = os.path.join(save_path, save_filename)
                            
                            with open(full_save_path, 'wb') as f:
                                f.write(file_data)
                            
                            attachment_info['saved_path'] = full_save_path
                            attachment_info['saved_filename'] = save_filename
                        
                        attachments_list.append(attachment_info)
                        
                    except Exception as e:
                        print(f"Error downloading attachment {part['filename']}: {str(e)}")
                        continue
        
        # Start processing from payload
        if 'parts' in message['payload']:
            process_parts(message['payload']['parts'], attachments)
        else:
            # Single part message
            process_parts([message['payload']], attachments)
        
        return attachments
        
    except Exception as e:
        print(f"Error extracting attachments from message {message_id}: {str(e)}")
        return []



@mcp.tool()
def gmail_read_last_email_attachments(
    max_days_back: int = 7,
    sender_filter: Optional[str] = None,
    subject_filter: Optional[str] = None,
    read_text_content: bool = True,
    max_attachment_size_mb: int = 10
) -> str:
    """
    Read attachments from the most recent email with attachments
    
    Args:
        max_days_back: How many days back to search for emails (default: 7)
        sender_filter: Optional filter by sender email (e.g., "john@example.com")
        subject_filter: Optional filter by subject keywords
        read_text_content: Whether to read and return text content of attachments
        max_attachment_size_mb: Maximum attachment size to process in MB
    """
    try:
        # Build search query for recent emails with attachments
        query_parts = ["has:attachment"]
        
        # Add date filter
        from datetime import datetime, timedelta
        date_filter = datetime.now() - timedelta(days=max_days_back)
        query_parts.append(f"after:{date_filter.strftime('%Y/%m/%d')}")
        
        # Add optional filters
        if sender_filter:
            query_parts.append(f"from:{sender_filter}")
        if subject_filter:
            query_parts.append(f'subject:"{subject_filter}"')
        
        search_query = " ".join(query_parts)
        
        # Search for messages
        results = gmail_service.users().messages().list(
            userId='me',
            q=search_query,
            maxResults=1  # Get only the most recent
        ).execute()
        
        messages = results.get('messages', [])
        
        if not messages:
            return "No recent emails with attachments found in the specified time period."
        
        # Get the most recent message
        message_id = messages[0]['id']
        
        # Get full message details
        message = gmail_service.users().messages().get(
            userId='me',
            id=message_id,
            format='full'
        ).execute()
        
        # Extract email metadata
        headers = message['payload'].get('headers', [])
        email_subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
        email_date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown Date')
        
        response = f"📧 **Last Email with Attachments**\n\n"
        response += f"**Subject:** {email_subject}\n"
        response += f"**From:** {sender}\n"
        response += f"**Date:** {email_date}\n"
        response += f"**Message ID:** {message_id}\n\n"
        
        # Process attachments
        attachments_processed = []
        
        def process_message_parts(parts):
            for part in parts:
                # Check for nested parts
                if 'parts' in part:
                    process_message_parts(part['parts'])
                    continue
                
                # Check if part is an attachment
                if part.get('filename') and part['body'].get('attachmentId'):
                    filename = part['filename']
                    mime_type = part['mimeType']
                    size = part['body'].get('size', 0)
                    attachment_id = part['body']['attachmentId']
                    
                    # Check size limit
                    size_mb = size / (1024 * 1024) if size else 0
                    if size_mb > max_attachment_size_mb:
                        attachments_processed.append({
                            'filename': filename,
                            'size': size,
                            'mime_type': mime_type,
                            'status': f'Skipped - too large ({size_mb:.1f}MB > {max_attachment_size_mb}MB limit)',
                            'content': None
                        })
                        continue
                    
                    try:
                        # Download attachment
                        attachment_data = gmail_service.users().messages().attachments().get(
                            userId='me',
                            messageId=message_id,
                            id=attachment_id
                        ).execute()
                        
                        # Decode attachment data
                        file_data = base64.urlsafe_b64decode(attachment_data['data'])
                        
                        attachment_info = {
                            'filename': filename,
                            'size': size,
                            'mime_type': mime_type,
                            'status': 'Successfully processed',
                            'content': None
                        }
                        
                        # Process different file types
                        if read_text_content:
                            if mime_type.startswith('text/'):
                                try:
                                    content = file_data.decode('utf-8')
                                    attachment_info['content'] = content[:2000] + "..." if len(content) > 2000 else content
                                except:
                                    attachment_info['content'] = "Could not decode text content"
                            
                            elif mime_type == 'application/pdf':
                                try:
                                    # Use existing PDF extraction function
                                    pdf_content = extract_pdf_text(io.BytesIO(file_data))
                                    attachment_info['content'] = pdf_content[:2000] + "..." if len(pdf_content) > 2000 else pdf_content
                                except:
                                    attachment_info['content'] = "Could not extract PDF text"
                            
                            elif mime_type in ['application/json', 'application/xml']:
                                try:
                                    content = file_data.decode('utf-8')
                                    attachment_info['content'] = content[:2000] + "..." if len(content) > 2000 else content
                                except:
                                    attachment_info['content'] = "Could not decode content"
                            
                            else:
                                attachment_info['content'] = f"Binary file - {mime_type} (use specific tools to process)"
                        
                        attachments_processed.append(attachment_info)
                        
                    except Exception as e:
                        attachments_processed.append({
                            'filename': filename,
                            'size': size,
                            'mime_type': mime_type,
                            'status': f'Error processing: {str(e)}',
                            'content': None
                        })
        
        # Start processing from payload
        if 'parts' in message['payload']:
            process_message_parts(message['payload']['parts'])
        else:
            process_message_parts([message['payload']])
        
        if not attachments_processed:
            response += "No attachments found in this email."
            return response
        
        response += f"**Attachments ({len(attachments_processed)}):**\n\n"
        
        for i, attachment in enumerate(attachments_processed, 1):
            response += f"**{i}. {attachment['filename']}**\n"
            response += f"   - Type: {attachment['mime_type']}\n"
            response += f"   - Size: {format_file_size(str(attachment['size']))}\n"
            response += f"   - Status: {attachment['status']}\n"
            
            if attachment['content']:
                response += f"   - Content Preview:\n``````\n"
            
            response += "\n"
        
        return response
        
    except Exception as e:
        return f"Error reading last email attachments: {str(e)}"


@mcp.tool()
def gmail_send_message(to: str, subject: str, body: str) -> str:
    """Send an email"""
    try:
        # Get user's email from profile
        profile = gmail_service.users().getProfile(userId='me').execute()
        from_email = profile['emailAddress']
        
        msg = MIMEText(body)
        msg['to'] = to
        msg['from'] = from_email
        msg['subject'] = subject
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        
        result = gmail_service.users().messages().send(
            userId='me', body={'raw': raw}
        ).execute()
        
        return json.dumps(result, indent=2)
    except HttpError as e:
        return json.dumps({'error': str(e)}, indent=2)

@mcp.tool()
def gmail_list_labels() -> str:
    """List all labels in the mailbox"""
    try:
        response = gmail_service.users().labels().list(userId='me').execute()
        labels = response.get('labels', [])
        return json.dumps(labels, indent=2)
    except HttpError as e:
        return json.dumps({'error': str(e)}, indent=2)

@mcp.tool()
def gmail_modify_labels(
    message_id: str,
    add_labels: Optional[List[str]] = None,
    remove_labels: Optional[List[str]] = None
) -> str:
    """Add or remove labels on an email"""
    try:
        add = add_labels or []
        remove = remove_labels or []
        body = {'addLabelIds': add, 'removeLabelIds': remove}
        
        result = gmail_service.users().messages().modify(
            userId='me', id=message_id, body=body
        ).execute()
        
        return json.dumps(result, indent=2)
    except HttpError as e:
        return json.dumps({'error': str(e)}, indent=2)

@mcp.tool()
def gmail_delete_message(message_id: str) -> str:
    """Delete an email by ID"""
    try:
        gmail_service.users().messages().delete(userId='me', id=message_id).execute()
        return json.dumps({'status': 'deleted', 'message_id': message_id}, indent=2)
    except HttpError as e:
        return json.dumps({'error': str(e)}, indent=2)

@mcp.tool()
def gmail_send_with_drive_attachment(to: str, subject: str, body: str, drive_file_id: str, 
                                   share_with_recipient: bool = True) -> str:
    """Send email with Google Drive file link and optionally share the file
    
    Args:
        to: Recipient email
        subject: Email subject
        body: Email body
        drive_file_id: Google Drive file ID to attach/link
        share_with_recipient: Whether to share the Drive file with recipient
    """
    try:
        # Get file info
        file_metadata = drive_service.files().get(
            fileId=drive_file_id, 
            fields='name,webViewLink'
        ).execute()
        
        file_name = file_metadata['name']
        file_link = file_metadata['webViewLink']
        
        # Share file with recipient if requested
        if share_with_recipient:
            try:
                permission = {
                    'type': 'user',
                    'role': 'reader',
                    'emailAddress': to
                }
                drive_service.permissions().create(
                    fileId=drive_file_id,
                    body=permission,
                    sendNotificationEmail=False  # We'll send our own email
                ).execute()
                share_status = "File has been shared with recipient."
            except Exception as e:
                share_status = f"Warning: Could not share file - {str(e)}"
        else:
            share_status = "File not shared (share_with_recipient=False)."
        
        # Enhanced email body with file link
        enhanced_body = f"{body}\n\n---\nAttached Google Drive File: {file_name}\nLink: {file_link}\n\n{share_status}"
        
        # Send email
        profile = gmail_service.users().getProfile(userId='me').execute()
        from_email = profile['emailAddress']
        
        msg = MIMEText(enhanced_body)
        msg['to'] = to
        msg['from'] = from_email
        msg['subject'] = subject
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        
        result = gmail_service.users().messages().send(
            userId='me', body={'raw': raw}
        ).execute()
        
        return f"Email sent successfully with Drive file link!\nMessage ID: {result['id']}\nFile: {file_name}\nLink: {file_link}\nShare status: {share_status}"
    
    except Exception as e:
        return f"Error sending email with Drive attachment: {str(e)}"

@mcp.tool()
def gmail_search_and_summarize(
    query: Optional[str] = None,
    sender: Optional[str] = None, 
    recipient: Optional[str] = None,
    subject_contains: Optional[str] = None,
    max_results: int = 10
) -> str:
    """
    Search emails by sender, recipient, subject, or content and provide summaries.
    
    Args:
        query: Search query for email content
        sender: Filter by sender email/name
        recipient: Filter by recipient email/name  
        subject_contains: Filter by subject content
        max_results: Maximum number of emails to return (default: 10)
    """
    try:
        # Build Gmail search query
        search_parts = []
        
        if sender:
            search_parts.append(f"from:({sender})")
        if recipient:
            search_parts.append(f"to:({recipient})")
        if subject_contains:
            search_parts.append(f"subject:({subject_contains})")
        if query:
            search_parts.append(f"({query})")
            
        # If no specific filters, search recent emails
        if not search_parts:
            gmail_query = "in:inbox"
        else:
            gmail_query = " ".join(search_parts)
        
        # Search for messages
        results = gmail_service.users().messages().list(
            userId='me',
            q=gmail_query,
            maxResults=max_results
        ).execute()
        
        messages = results.get('messages', [])
        
        if not messages:
            return f"No emails found matching the search criteria: {gmail_query}"
        
        # Get detailed information for each message
        email_summaries = []
        
        for msg in messages:
            try:
                # Get full message details
                message = gmail_service.users().messages().get(
                    userId='me', 
                    id=msg['id'],
                    format='full'
                ).execute()
                
                # Extract headers
                headers = message['payload'].get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                sender_email = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                recipient_email = next((h['value'] for h in headers if h['name'] == 'To'), 'Unknown Recipient')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown Date')
                
                # Extract email body
                body = ""
                if 'parts' in message['payload']:
                    for part in message['payload']['parts']:
                        if part['mimeType'] == 'text/plain' and 'data' in part['body']:
                            body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                            break
                        elif part['mimeType'] == 'text/html' and 'data' in part['body']:
                            body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                            break
                elif 'body' in message['payload'] and 'data' in message['payload']['body']:
                    body = base64.urlsafe_b64decode(message['payload']['body']['data']).decode('utf-8')
                
                # Create summary (first 200 characters of body)
                body_summary = body[:200] + "..." if len(body) > 200 else body
                
                # Clean up sender name (remove email brackets if present)
                sender_clean = sender_email.split('<')[0].strip().strip('"') if '<' in sender_email else sender_email
                
                email_summary = {
                    'id': msg['id'],
                    'subject': subject,
                    'sender': sender_clean,
                    'sender_email': sender_email,
                    'recipient': recipient_email,
                    'date': date,
                    'body_preview': body_summary.replace('\n', ' ').replace('\r', ' ').strip()
                }
                
                email_summaries.append(email_summary)
                
            except Exception as e:
                email_summaries.append({
                    'id': msg['id'],
                    'error': f"Could not process email: {str(e)}"
                })
        
        # Format the response
        response = f"Found {len(email_summaries)} emails matching search criteria:\n"
        response += f"Search Query: {gmail_query}\n\n"
        
        for i, email in enumerate(email_summaries, 1):
            if 'error' in email:
                response += f"{i}. Email ID: {email['id']} - {email['error']}\n\n"
            else:
                response += f"{i}. Subject: {email['subject']}\n"
                response += f"   From: {email['sender']}\n"
                response += f"   To: {email['recipient']}\n"
                response += f"   Date: {email['date']}\n"
                response += f"   Preview: {email['body_preview']}\n"
                response += f"   Email ID: {email['id']}\n\n"
        
        return response
        
    except Exception as e:
        return f"Error searching emails: {str(e)}"

@mcp.tool()
def gmail_send_file_attachment(
    to: str, 
    subject: str, 
    body: str, 
    file_path: str, 
    attachment_name: Optional[str] = None
) -> str:
    """
    Send an email with file attachment
    
    Args:
        to: Recipient email address
        subject: Email subject
        body: Email body text
        file_path: Path to the file to attach (from uploads directory)
        attachment_name: Optional custom name for the attachment (defaults to original filename)
    """
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            return f"Error: File not found at {file_path}"
        
        # Get user's email from profile
        profile = gmail_service.users().getProfile(userId='me').execute()
        from_email = profile['emailAddress']
        
        # Create multipart message
        msg = MIMEMultipart()
        msg['to'] = to
        msg['from'] = from_email
        msg['subject'] = subject
        
        # Add body to email
        msg.attach(MIMEText(body, 'plain'))
        
        # Get file info
        original_filename = os.path.basename(file_path)
        attach_filename = attachment_name if attachment_name else original_filename
        
        # Detect MIME type
        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = 'application/octet-stream'
        
        # Read and attach file
        with open(file_path, 'rb') as attachment_file:
            file_data = attachment_file.read()
        
        # Create attachment
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(file_data)
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename= {attach_filename}'
        )
        
        # Attach the file to the message
        msg.attach(part)
        
        # Convert to base64 encoded string
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        
        # Send email
        result = gmail_service.users().messages().send(
            userId='me', 
            body={'raw': raw}
        ).execute()
        
        # Get file size for response
        file_size = os.path.getsize(file_path)
        
        response = f"Email with attachment sent successfully!\n"
        response += f"Message ID: {result['id']}\n"
        response += f"To: {to}\n"
        response += f"Subject: {subject}\n"
        response += f"Attachment: {attach_filename}\n"
        response += f"File Size: {file_size} bytes\n"
        response += f"MIME Type: {mime_type}\n"
        
        return response
        
    except HttpError as e:
        return f"Gmail API error: {str(e)}"
    except Exception as e:
        return f"Error sending email with attachment: {str(e)}"


@mcp.tool()
def gmail_send_multiple_attachments(
    to: str, 
    subject: str, 
    body: str, 
    file_paths: List[str]
) -> str:
    """
    Send an email with multiple file attachments
    
    Args:
        to: Recipient email address
        subject: Email subject
        body: Email body text
        file_paths: List of file paths to attach (from uploads directory)
    """
    try:
        # Check if all files exist
        missing_files = []
        for file_path in file_paths:
            if not os.path.exists(file_path):
                missing_files.append(file_path)
        
        if missing_files:
            return f"Error: Files not found: {', '.join(missing_files)}"
        
        # Get user's email from profile
        profile = gmail_service.users().getProfile(userId='me').execute()
        from_email = profile['emailAddress']
        
        # Create multipart message
        msg = MIMEMultipart()
        msg['to'] = to
        msg['from'] = from_email
        msg['subject'] = subject
        
        # Add body to email
        msg.attach(MIMEText(body, 'plain'))
        
        attached_files = []
        total_size = 0
        
        # Process each file
        for file_path in file_paths:
            # Get file info
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            total_size += file_size
            
            # Detect MIME type
            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = 'application/octet-stream'
            
            # Read and attach file
            with open(file_path, 'rb') as attachment_file:
                file_data = attachment_file.read()
            
            # Create attachment
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(file_data)
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {filename}'
            )
            
            # Attach the file to the message
            msg.attach(part)
            
            attached_files.append({
                'name': filename,
                'size': file_size,
                'mime_type': mime_type
            })
        
        # Convert to base64 encoded string
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        
        # Send email
        result = gmail_service.users().messages().send(
            userId='me', 
            body={'raw': raw}
        ).execute()
        
        response = f"Email with {len(attached_files)} attachments sent successfully!\n"
        response += f"Message ID: {result['id']}\n"
        response += f"To: {to}\n"
        response += f"Subject: {subject}\n"
        response += f"Total Size: {total_size} bytes\n\n"
        response += "Attachments:\n"
        
        for i, file_info in enumerate(attached_files, 1):
            response += f"{i}. {file_info['name']} ({file_info['size']} bytes, {file_info['mime_type']})\n"
        
        return response
        
    except HttpError as e:
        return f"Gmail API error: {str(e)}"
    except Exception as e:
        return f"Error sending email with attachments: {str(e)}"

@mcp.tool()
def drive_move(fileId: str, targetFolderId: str) -> str:
    """Move a file to a different folder in Google Drive"""
    try:
        # Get current parents
        file = drive_service.files().get(fileId=fileId, fields='parents').execute()
        previous_parents = ','.join(file.get('parents', []))
        
        # Move file
        file = drive_service.files().update(
            fileId=fileId,
            addParents=targetFolderId,
            removeParents=previous_parents,
            fields='id, name, parents'
        ).execute()
        
        return f"File moved successfully: {file['name']} (ID: {file['id']}) to folder ID: {targetFolderId}"
    
    except Exception as e:
        return f"Error moving file {fileId}: {str(e)}"
if __name__=="__main__":
    mcp.transport("stdio")
    
import base64
import json
import os
import mimetypes
import io
from typing import Optional, List, Dict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
import re
from html import unescape
from googleapiclient.errors import HttpError

# HTML stripping utility
def strip_html_tags(html_content):
    """Remove HTML tags and convert to clean text"""
    if not html_content:
        return ""
    
    # Remove HTML tags
    clean = re.sub('<.*?>', '', html_content)
    # Decode HTML entities
    clean = unescape(clean)
    # Clean up whitespace
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean

def format_file_size(size_str):
    """Format file size in human readable format"""
    try:
        size = int(size_str)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    except:
        return size_str

@mcp.tool()
def gmail_list_messages(max_results: int = 10, query: Optional[str] = None) -> str:
    """List recent emails with clean, AI-friendly format"""
    try:
        params = {'userId': 'me', 'maxResults': max_results}
        if query:
            params['q'] = query
        response = gmail_service.users().messages().list(**params).execute()
        messages = response.get('messages', [])
        
        if not messages:
            return "No messages found."
        
        # Get clean info for each message
        message_list = []
        for msg in messages:
            try:
                full_msg = gmail_service.users().messages().get(
                    userId='me', id=msg['id'], format='metadata',
                    metadataHeaders=['From', 'Subject', 'Date', 'To']
                ).execute()
                
                headers = full_msg.get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                from_addr = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                to_addr = next((h['value'] for h in headers if h['name'] == 'To'), 'Unknown Recipient')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown Date')
                
                # Clean sender name (extract name from "Name <email>" format)
                sender_clean = from_addr.split('<')[0].strip().strip('"') if '<' in from_addr else from_addr
                
                message_list.append(f"ID: {msg['id']}\nSubject: {subject}\nFrom: {sender_clean}\nTo: {to_addr}\nDate: {date}\n")
                
            except Exception as e:
                message_list.append(f"ID: {msg['id']}\nError: Could not fetch details - {str(e)}\n")
        
        return "\n" + "="*50 + "\n".join(message_list)
    
    except HttpError as e:
        return f"Gmail API Error: {str(e)}"

@mcp.tool()
def gmail_read_message(message_id: str, include_attachments_info: bool = True) -> str:
    """Read email content in clean, AI-friendly format with optional attachment info"""
    try:
        message = gmail_service.users().messages().get(
            userId='me', id=message_id, format='full'
        ).execute()

        # Extract headers
        headers = message.get('payload', {}).get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
        recipient = next((h['value'] for h in headers if h['name'] == 'To'), 'Unknown Recipient')
        date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown Date')
        
        # Clean sender name
        sender_clean = sender.split('<')[0].strip().strip('"') if '<' in sender else sender
        
        # Extract body text
        body = extract_email_body(message.get('payload', {}))
        
        # Format response
        response = f"EMAIL DETAILS:\n"
        response += f"Message ID: {message_id}\n"
        response += f"Subject: {subject}\n"
        response += f"From: {sender_clean}\n"
        response += f"To: {recipient}\n"
        response += f"Date: {date}\n\n"
        response += f"BODY:\n{body}\n"
        
        # Add attachment info if requested
        if include_attachments_info:
            attachments = get_attachment_info(message.get('payload', {}))
            if attachments:
                response += f"\nATTACHMENTS ({len(attachments)}):\n"
                for i, att in enumerate(attachments, 1):
                    response += f"{i}. {att['filename']} ({att['size']}, {att['mime_type']})\n"
            else:
                response += "\nNo attachments found.\n"

        return response

    except HttpError as e:
        return f"Gmail API Error: {str(e)}"
    except Exception as e:
        return f"Error reading message: {str(e)}"

def extract_email_body(payload):
    """Extract clean text body from email payload"""
    # Try to get plain text first
    plain_text = extract_text_from_payload(payload, 'text/plain')
    if plain_text:
        return plain_text
    
    # Fall back to HTML and strip tags
    html_text = extract_text_from_payload(payload, 'text/html')
    if html_text:
        return strip_html_tags(html_text)
    
    return "No readable text content found."

def extract_text_from_payload(payload, mime_type):
    """Recursively extract text of specific MIME type from payload"""
    if payload.get('mimeType') == mime_type:
        data = payload.get('body', {}).get('data')
        if data:
            try:
                return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
            except:
                return None

    for part in payload.get('parts', []):
        result = extract_text_from_payload(part, mime_type)
        if result:
            return result

    return None

def get_attachment_info(payload):
    """Get basic attachment information without downloading"""
    attachments = []
    
    def process_parts(parts):
        for part in parts:
            if 'parts' in part:
                process_parts(part['parts'])
            elif part.get('filename') and part['body'].get('attachmentId'):
                attachments.append({
                    'filename': part['filename'],
                    'mime_type': part['mimeType'],
                    'size': format_file_size(str(part['body'].get('size', 0))),
                    'attachment_id': part['body']['attachmentId']
                })
    
    if 'parts' in payload:
        process_parts(payload['parts'])
    
    return attachments

@mcp.tool()
def gmail_read_attachments(
    message_id: Optional[str] = None,
    sender: Optional[str] = None,
    subject_contains: Optional[str] = None,
    days_back: int = 7,
    max_results: int = 5,
    max_attachment_size_mb: int = 10,
    read_text_content: bool = True
) -> str:
    """
    Efficiently read email attachments with flexible search options
    
    Args:
        message_id: Specific email ID to read attachments from
        sender: Filter by sender email/name  
        subject_contains: Filter by subject keywords
        days_back: How many days back to search (default: 7)
        max_results: Max emails to process (default: 5)
        max_attachment_size_mb: Max attachment size to process in MB
        read_text_content: Whether to extract and preview text content
    """
    try:
        # If specific message ID provided, process that email only
        if message_id:
            return process_single_email_attachments(message_id, max_attachment_size_mb, read_text_content)
        
        # Build search query for emails with attachments
        query_parts = ["has:attachment"]
        
        # Add date filter
        date_filter = datetime.now() - timedelta(days=days_back)
        query_parts.append(f"after:{date_filter.strftime('%Y/%m/%d')}")
        
        # Add optional filters
        if sender:
            query_parts.append(f"from:({sender})")
        if subject_contains:
            query_parts.append(f'subject:"{subject_contains}"')
        
        search_query = " ".join(query_parts)
        
        # Search for messages
        results = gmail_service.users().messages().list(
            userId='me',
            q=search_query,
            maxResults=max_results
        ).execute()
        
        messages = results.get('messages', [])
        
        if not messages:
            return f"No emails with attachments found.\nSearch criteria: {search_query}"
        
        response = f"FOUND {len(messages)} EMAIL(S) WITH ATTACHMENTS\n"
        response += f"Search Query: {search_query}\n\n"
        
        # Process each email
        for i, message in enumerate(messages, 1):
            try:
                email_response = process_single_email_attachments(
                    message['id'], max_attachment_size_mb, read_text_content
                )
                response += f"EMAIL {i}:\n{email_response}\n"
                response += "="*60 + "\n"
                
            except Exception as e:
                response += f"EMAIL {i}: Error processing {message['id']} - {str(e)}\n"
                continue
        
        return response
        
    except Exception as e:
        return f"Error reading attachments: {str(e)}"

def process_single_email_attachments(message_id: str, max_size_mb: int, read_content: bool) -> str:
    """Process attachments from a single email"""
    try:
        # Get full message
        message = gmail_service.users().messages().get(
            userId='me', id=message_id, format='full'
        ).execute()
        
        # Extract email metadata
        headers = message['payload'].get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
        date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown Date')
        
        sender_clean = sender.split('<')[0].strip().strip('"') if '<' in sender else sender
        
        response = f"Subject: {subject}\n"
        response += f"From: {sender_clean}\n"
        response += f"Date: {date}\n"
        response += f"Message ID: {message_id}\n\n"
        
        # Process attachments
        attachments = extract_attachments_from_message(message_id, message['payload'], max_size_mb, read_content)
        
        if not attachments:
            return response + "No attachments found in this email."
        
        response += f"ATTACHMENTS ({len(attachments)}):\n"
        
        for i, attachment in enumerate(attachments, 1):
            response += f"\n{i}. {attachment['filename']}\n"
            response += f"   Type: {attachment['mime_type']}\n"
            response += f"   Size: {attachment['size']}\n"
            response += f"   Status: {attachment['status']}\n"
            
            if attachment.get('content_preview'):
                response += f"   Content Preview:\n   {attachment['content_preview'][:300]}...\n"
        
        return response
        
    except Exception as e:
        return f"Error processing email {message_id}: {str(e)}"

def extract_attachments_from_message(message_id: str, payload: dict, max_size_mb: int, read_content: bool) -> List[Dict]:
    """Extract and optionally read attachment content from message payload"""
    attachments = []
    
    def process_parts(parts):
        for part in parts:
            if 'parts' in part:
                process_parts(part['parts'])
            elif part.get('filename') and part['body'].get('attachmentId'):
                filename = part['filename']
                mime_type = part['mimeType']
                size_bytes = part['body'].get('size', 0)
                attachment_id = part['body']['attachmentId']
                
                # Check size limit
                size_mb = size_bytes / (1024 * 1024) if size_bytes else 0
                
                attachment_info = {
                    'filename': filename,
                    'mime_type': mime_type,
                    'size': format_file_size(str(size_bytes)),
                    'attachment_id': attachment_id
                }
                
                if size_mb > max_size_mb:
                    attachment_info['status'] = f'Skipped - too large ({size_mb:.1f}MB > {max_size_mb}MB)'
                    attachment_info['content_preview'] = None
                else:
                    try:
                        # Download attachment data
                        attachment_data = gmail_service.users().messages().attachments().get(
                            userId='me',
                            messageId=message_id,
                            id=attachment_id
                        ).execute()
                        
                        file_data = base64.urlsafe_b64decode(attachment_data['data'])
                        attachment_info['status'] = 'Successfully downloaded'
                        
                        # Extract content preview if requested
                        if read_content:
                            attachment_info['content_preview'] = extract_attachment_content(file_data, mime_type)
                        else:
                            attachment_info['content_preview'] = None
                            
                    except Exception as e:
                        attachment_info['status'] = f'Download failed: {str(e)}'
                        attachment_info['content_preview'] = None
                
                attachments.append(attachment_info)
    
    if 'parts' in payload:
        process_parts(payload['parts'])
    
    return attachments

def extract_attachment_content(file_data: bytes, mime_type: str) -> str:
    """Extract readable content from attachment based on MIME type"""
    try:
        if mime_type.startswith('text/'):
            return file_data.decode('utf-8', errors='ignore')
        
        elif mime_type == 'application/json':
            return file_data.decode('utf-8', errors='ignore')
        
        elif mime_type in ['application/xml', 'text/xml']:
            return file_data.decode('utf-8', errors='ignore')
        
        elif mime_type == 'application/pdf':
            # Basic PDF text extraction (you'd need PyPDF2 or similar for full extraction)
            text = file_data.decode('utf-8', errors='ignore')
            # Remove PDF binary parts and keep readable text
            cleaned = re.sub(r'[^\x20-\x7E\n\r\t]', '', text)
            return cleaned if cleaned.strip() else "PDF content (binary - use PDF reader)"
        
        else:
            return f"Binary file ({mime_type}) - {len(file_data)} bytes"
            
    except Exception as e:
        return f"Content extraction failed: {str(e)}"

@mcp.tool()
def gmail_search_and_summarize(
    query: Optional[str] = None,
    sender: Optional[str] = None, 
    recipient: Optional[str] = None,
    subject_contains: Optional[str] = None,
    max_results: int = 10
) -> str:
    """Search emails with clean, summarized results"""
    try:
        # Build search query
        search_parts = []
        
        if sender:
            search_parts.append(f"from:({sender})")
        if recipient:
            search_parts.append(f"to:({recipient})")
        if subject_contains:
            search_parts.append(f"subject:({subject_contains})")
        if query:
            search_parts.append(f"({query})")
            
        gmail_query = " ".join(search_parts) if search_parts else "in:inbox"
        
        # Search messages
        results = gmail_service.users().messages().list(
            userId='me',
            q=gmail_query,
            maxResults=max_results
        ).execute()
        
        messages = results.get('messages', [])
        
        if not messages:
            return f"No emails found for query: {gmail_query}"
        
        response = f"SEARCH RESULTS ({len(messages)} emails):\n"
        response += f"Query: {gmail_query}\n\n"
        
        # Process each message
        for i, msg in enumerate(messages, 1):
            try:
                message = gmail_service.users().messages().get(
                    userId='me', id=msg['id'], format='full'
                ).execute()
                
                # Extract headers
                headers = message['payload'].get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')
                
                sender_clean = sender.split('<')[0].strip().strip('"') if '<' in sender else sender
                
                # Get body preview
                body = extract_email_body(message['payload'])
                body_preview = body[:200].replace('\n', ' ').strip() + "..." if len(body) > 200 else body
                
                response += f"{i}. {subject}\n"
                response += f"   From: {sender_clean}\n"
                response += f"   Date: {date}\n"
                response += f"   Preview: {body_preview}\n"
                response += f"   ID: {msg['id']}\n\n"
                
            except Exception as e:
                response += f"{i}. Error processing email {msg['id']}: {str(e)}\n\n"
        
        return response
        
    except Exception as e:
        return f"Search error: {str(e)}"

@mcp.tool()
def gmail_send_message(to: str, subject: str, body: str) -> str:
    """Send an email - returns clean confirmation"""
    try:
        profile = gmail_service.users().getProfile(userId='me').execute()
        from_email = profile['emailAddress']
        
        msg = MIMEText(body)
        msg['to'] = to
        msg['from'] = from_email
        msg['subject'] = subject
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        
        result = gmail_service.users().messages().send(
            userId='me', body={'raw': raw}
        ).execute()
        
        return f"Email sent successfully!\nMessage ID: {result['id']}\nTo: {to}\nSubject: {subject}"
        
    except Exception as e:
        return f"Failed to send email: {str(e)}"

@mcp.tool() 
def gmail_list_labels() -> str:
    """List Gmail labels in clean format"""
    try:
        response = gmail_service.users().labels().list(userId='me').execute()
        labels = response.get('labels', [])
        
        if not labels:
            return "No labels found."
        
        result = "GMAIL LABELS:\n"
        for label in labels:
            result += f"- {label['name']} (ID: {label['id']})\n"
        
        return result
        
    except Exception as e:
        return f"Error listing labels: {str(e)}"

@mcp.tool()
def gmail_modify_labels(
    message_id: str,
    add_labels: Optional[List[str]] = None,
    remove_labels: Optional[List[str]] = None
) -> str:
    """Add or remove labels - returns simple confirmation"""
    try:
        add = add_labels or []
        remove = remove_labels or []
        body = {'addLabelIds': add, 'removeLabelIds': remove}
        
        gmail_service.users().messages().modify(
            userId='me', id=message_id, body=body
        ).execute()
        
        actions = []
        if add:
            actions.append(f"Added: {', '.join(add)}")
        if remove:
            actions.append(f"Removed: {', '.join(remove)}")
        
        return f"Labels updated for message {message_id}\n{' | '.join(actions)}"
        
    except Exception as e:
        return f"Error modifying labels: {str(e)}"

@mcp.tool()
def gmail_delete_message(message_id: str) -> str:
    """Delete an email - returns simple confirmation"""
    try:
        gmail_service.users().messages().delete(userId='me', id=message_id).execute()
        return f"Email {message_id} deleted successfully."
    except Exception as e:
        return f"Error deleting email: {str(e)}"

@mcp.tool()
def gmail_send_with_drive_attachment(
    to: str, subject: str, body: str, drive_file_id: str, 
    share_with_recipient: bool = True
) -> str:
    """Send email with Google Drive file link"""
    try:
        # Get file info
        file_metadata = drive_service.files().get(
            fileId=drive_file_id, 
            fields='name,webViewLink'
        ).execute()
        
        file_name = file_metadata['name']
        file_link = file_metadata['webViewLink']
        
        # Share file if requested
        share_status = "not shared"
        if share_with_recipient:
            try:
                permission = {
                    'type': 'user',
                    'role': 'reader', 
                    'emailAddress': to
                }
                drive_service.permissions().create(
                    fileId=drive_file_id,
                    body=permission,
                    sendNotificationEmail=False
                ).execute()
                share_status = "shared with recipient"
            except:
                share_status = "sharing failed"
        
        # Enhanced email body
        enhanced_body = f"{body}\n\n---\nAttached Google Drive File: {file_name}\nLink: {file_link}"
        
        # Send email
        profile = gmail_service.users().getProfile(userId='me').execute()
        from_email = profile['emailAddress']
        
        msg = MIMEText(enhanced_body)
        msg['to'] = to
        msg['from'] = from_email
        msg['subject'] = subject
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        
        result = gmail_service.users().messages().send(
            userId='me', body={'raw': raw}
        ).execute()
        
        return f"Email sent with Drive file!\nMessage ID: {result['id']}\nFile: {file_name} ({share_status})\nLink: {file_link}"
    
    except Exception as e:
        return f"Error sending email with Drive attachment: {str(e)}"

@mcp.tool()
def gmail_send_multiple_attachments(
    to: str, subject: str, body: str, file_paths: List[str]
) -> str:
    """Send email with multiple file attachments"""
    try:
        # Check files exist
        missing_files = [f for f in file_paths if not os.path.exists(f)]
        if missing_files:
            return f"Files not found: {', '.join(missing_files)}"
        
        # Get sender info
        profile = gmail_service.users().getProfile(userId='me').execute()
        from_email = profile['emailAddress']
        
        # Create multipart message
        msg = MIMEMultipart()
        msg['to'] = to
        msg['from'] = from_email
        msg['subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        attached_files = []
        total_size = 0
        
        # Attach files
        for file_path in file_paths:
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            total_size += file_size
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(file_data)
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename= {filename}')
            msg.attach(part)
            
            attached_files.append({'name': filename, 'size': format_file_size(str(file_size))})
        
        # Send email
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        result = gmail_service.users().messages().send(userId='me', body={'raw': raw}).execute()
        
        files_info = ", ".join([f"{f['name']} ({f['size']})" for f in attached_files])
        return f"Email sent with {len(attached_files)} attachments!\nMessage ID: {result['id']}\nFiles: {files_info}\nTotal Size: {format_file_size(str(total_size))}"
        
    except Exception as e:
        return f"Error sending email with attachments: {str(e)}"