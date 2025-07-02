
def clean_html_content(html_content: str) -> str:
    """Clean HTML content and extract readable text"""
    if not html_content:
        return ""
    
    # Remove HTML tags
    clean_text = re.sub(r'<[^>]+>', '', html_content)
    # Clean up whitespace
    clean_text = re.sub(r'\s+', ' ', clean_text)
    # Remove common HTML entities
    clean_text = clean_text.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
    return clean_text.strip()

def extract_email_body(payload) -> str:
    """Extract clean text body from email payload"""
    body = ""
    
    def extract_from_parts(parts):
        nonlocal body
        for part in parts:
            if 'parts' in part:
                extract_from_parts(part['parts'])
            elif part.get('mimeType') == 'text/plain' and 'data' in part.get('body', {}):
                try:
                    decoded = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    body = decoded
                    return  # Prefer plain text
                except:
                    continue
            elif part.get('mimeType') == 'text/html' and 'data' in part.get('body', {}) and not body:
                try:
                    decoded = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    body = clean_html_content(decoded)
                except:
                    continue
    
    if 'parts' in payload:
        extract_from_parts(payload['parts'])
    elif 'body' in payload and 'data' in payload['body']:
        try:
            decoded = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')
            if payload.get('mimeType') == 'text/html':
                body = clean_html_content(decoded)
            else:
                body = decoded
        except:
            body = "Could not decode email body"
    
    return body[:2000] + "..." if len(body) > 2000 else body

@mcp.tool()
def gmail_list_messages(max_results: int = 10, query: Optional[str] = None) -> str:
    """List recent emails with clean, readable format"""
    try:
        params = {'userId': 'me', 'maxResults': max_results}
        if query:
            params['q'] = query
            
        response = gmail_service.users().messages().list(**params).execute()
        messages = response.get('messages', [])
        
        if not messages:
            return "No messages found."
        
        result = f"Found {len(messages)} emails:\n\n"
        
        for i, msg in enumerate(messages, 1):
            try:
                full_msg = gmail_service.users().messages().get(
                    userId='me', id=msg['id'], format='metadata',
                    metadataHeaders=['From', 'Subject', 'Date']
                ).execute()
                
                headers = full_msg.get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                from_addr = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown Date')
                
                # Clean sender name
                sender = from_addr.split('<')[0].strip().strip('"') if '<' in from_addr else from_addr
                
                result += f"{i}. {subject}\n"
                result += f"   From: {sender}\n"
                result += f"   Date: {date}\n"
                result += f"   ID: {msg['id']}\n\n"
                
            except Exception as e:
                result += f"{i}. Error loading message: {str(e)}\n\n"
        
        return result
    
    except Exception as e:
        return f"Error listing messages: {str(e)}"

@mcp.tool()
def gmail_read_email(message_id: str) -> str:
    """Read a specific email with clean formatting"""
    try:
        message = gmail_service.users().messages().get(
            userId='me', id=message_id, format='full'
        ).execute()
        
        # Extract headers
        headers = message.get('payload', {}).get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
        from_addr = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
        to_addr = next((h['value'] for h in headers if h['name'] == 'To'), 'Unknown')
        date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')
        
        # Extract body
        body = extract_email_body(message.get('payload', {}))
        
        # Clean sender name
        sender = from_addr.split('<')[0].strip().strip('"') if '<' in from_addr else from_addr
        
        result = f"Email Details:\n\n"
        result += f"Subject: {subject}\n"
        result += f"From: {sender}\n"
        result += f"To: {to_addr}\n"
        result += f"Date: {date}\n"
        result += f"Message ID: {message_id}\n\n"
        result += f"Content:\n{'-'*40}\n{body}\n"
        
        return result
        
    except Exception as e:
        return f"Error reading email {message_id}: {str(e)}"

@mcp.tool()
def gmail_send_message(to: str, subject: str, body: str) -> str:
    """Send a simple email"""
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
        return f"Error sending email: {str(e)}"


@mcp.tool()
def gmail_search_emails(
    query: Optional[str] = None,
    sender: Optional[str] = None,
    recipient: Optional[str] = None,
    subject_contains: Optional[str] = None,
    max_results: Optional[int] = 10
) -> str:
    """Search emails with filters and return clean summaries"""
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
            userId='me', q=gmail_query, maxResults=max_results
        ).execute()
        
        messages = results.get('messages', [])
        if not messages:
            return f"No emails found for query: {gmail_query}"
        
        result = f"Found {len(messages)} emails for: {gmail_query}\n\n"
        
        for i, msg in enumerate(messages, 1):
            try:
                message = gmail_service.users().messages().get(
                    userId='me', id=msg['id'], format='full'
                ).execute()
                
                headers = message['payload'].get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                from_addr = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')
                
                # Get body preview
                body = extract_email_body(message.get('payload', {}))
                preview = body[:150] + "..." if len(body) > 150 else body
                
                sender = from_addr.split('<')[0].strip().strip('"') if '<' in from_addr else from_addr
                
                result += f"{i}. {subject}\n"
                result += f"   From: {sender}\n"
                result += f"   Date: {date}\n"
                result += f"   Preview: {preview}\n"
                result += f"   ID: {msg['id']}\n\n"
                
            except Exception as e:
                result += f"{i}. Error processing email: {str(e)}\n\n"
        
        return result
        
    except Exception as e:
        return f"Error searching emails: {str(e)}"

@mcp.tool()
def gmail_list_labels() -> str:
    """List all Gmail labels in readable format"""
    try:
        response = gmail_service.users().labels().list(userId='me').execute()
        labels = response.get('labels', [])
        
        if not labels:
            return "No labels found."
        
        result = f"Gmail Labels ({len(labels)}):\n\n"
        
        # Separate system and user labels
        system_labels = []
        user_labels = []
        
        for label in labels:
            if label['type'] == 'system':
                system_labels.append(label)
            else:
                user_labels.append(label)
        
        if system_labels:
            result += "System Labels:\n"
            for label in sorted(system_labels, key=lambda x: x['name']):
                result += f"  - {label['name']} (ID: {label['id']})\n"
            result += "\n"
        
        if user_labels:
            result += "Custom Labels:\n"
            for label in sorted(user_labels, key=lambda x: x['name']):
                result += f"  - {label['name']} (ID: {label['id']})\n"
        
        return result
    
    except Exception as e:
        return f"Error listing labels: {str(e)}"

@mcp.tool()
def gmail_modify_labels(
    message_id: str,
    add_labels: Optional[List[str]] = None,
    remove_labels: Optional[List[str]] = None
) -> str:
    """Add or remove labels from an email"""
    try:
        add = add_labels or []
        remove = remove_labels or []
        body = {'addLabelIds': add, 'removeLabelIds': remove}
        
        result = gmail_service.users().messages().modify(
            userId='me', id=message_id, body=body
        ).execute()
        
        response = f"Labels modified for message {message_id}:\n"
        if add:
            response += f"  Added: {', '.join(add)}\n"
        if remove:
            response += f"  Removed: {', '.join(remove)}\n"
        
        return response
    
    except Exception as e:
        return f"Error modifying labels: {str(e)}"
@mcp.tool() #auth error
def gmail_delete_message(message_id: str) -> str:
    """Delete an email by ID"""
    try:
        gmail_service.users().messages().delete(userId='me', id=message_id).execute()
        return f"Email {message_id} deleted successfully"
    except Exception as e:
        return f"Error deleting email: {str(e)}"

@mcp.tool()
def gmail_send_with_drive_attachment(
    to: str, 
    subject: str, 
    body: str, 
    drive_file_id: str,
    share_with_recipient: bool = True
) -> str:
    """Send email with Google Drive file link and optionally share the file"""
    try:
        # Get file info
        file_metadata = drive_service.files().get(
            fileId=drive_file_id, fields='name,webViewLink'
        ).execute()
        
        file_name = file_metadata['name']
        file_link = file_metadata['webViewLink']
        
        # Share file if requested
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
                share_status = "shared"
            except Exception:
                share_status = "sharing failed"
        else:
            share_status = "not shared"
        
        # Enhanced email body
        enhanced_body = f"{body}\n\n---\nAttached File: {file_name}\nLink: {file_link}"
        
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
        
        return f"Email sent with Drive attachment!\nMessage ID: {result['id']}\nFile: {file_name} ({share_status})\nTo: {to}"
    
    except Exception as e:
        return f"Error sending email with Drive attachment: {str(e)}"

@mcp.tool()