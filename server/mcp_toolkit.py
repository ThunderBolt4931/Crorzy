#!/usr/bin/env python3
"""
MCP Toolkit for Google Workspace Integration using FastMCP
Receives authentication tokens via environment variables from the Node.js server
"""

import os
import sys
import json
import asyncio
import logging
import base64
import email
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

# Google API imports
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
import io

# FastMCP imports
try:
    from mcp import FastMCP
except ImportError:
    print("FastMCP library not found. Please install with: pip install mcp", file=sys.stderr)
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastMCP
mcp = FastMCP("Google Workspace MCP Server")

class GoogleWorkspaceClient:
    """Google Workspace API client with token management"""
    
    def __init__(self):
        self.credentials = None
        self.user_id = None
        self._services = {}
        self._initialize_credentials()
    
    def _initialize_credentials(self):
        """Initialize Google credentials from environment variables"""
        try:
            # Get user ID and token data from environment
            self.user_id = os.getenv('USER_ID')
            access_token = os.getenv('GOOGLE_ACCESS_TOKEN')
            refresh_token = os.getenv('GOOGLE_REFRESH_TOKEN')
            id_token = os.getenv('GOOGLE_ID_TOKEN')
            expires_at = os.getenv('GOOGLE_TOKEN_EXPIRES_AT')
            client_id = os.getenv('GOOGLE_CLIENT_ID')
            client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
            
            if not all([self.user_id, access_token, refresh_token, client_id, client_secret]):
                raise ValueError("Missing required authentication environment variables")
            
            # Parse expiry time
            expiry = None
            if expires_at:
                try:
                    expiry = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                except ValueError:
                    logger.warning(f"Invalid expiry format: {expires_at}")
            
            # Create credentials object
            self.credentials = Credentials(
                token=access_token,
                refresh_token=refresh_token,
                id_token=id_token,
                token_uri='https://oauth2.googleapis.com/token',
                client_id=client_id,
                client_secret=client_secret,
                expiry=expiry
            )
            
            # Refresh if needed
            if self.credentials.expired:
                logger.info("Refreshing expired credentials...")
                self.credentials.refresh(Request())
                logger.info("Credentials refreshed successfully")
            
            logger.info(f"Initialized credentials for user {self.user_id}")
            
        except Exception as e:
            logger.error(f"Failed to initialize credentials: {e}")
            raise
    
    def get_service(self, service_name: str, version: str):
        """Get or create a Google API service"""
        service_key = f"{service_name}_{version}"
        
        if service_key not in self._services:
            try:
                self._services[service_key] = build(
                    service_name, 
                    version, 
                    credentials=self.credentials
                )
                logger.info(f"Created {service_name} {version} service")
            except Exception as e:
                logger.error(f"Failed to create {service_name} service: {e}")
                raise
        
        return self._services[service_key]

# Global client instance
workspace_client = GoogleWorkspaceClient()

def create_email_message(to: str, subject: str, body: str, cc: str = None, bcc: str = None) -> str:
    """Create a base64 encoded email message"""
    message = email.mime.text.MIMEText(body)
    message['to'] = to
    message['subject'] = subject
    if cc:
        message['cc'] = cc
    if bcc:
        message['bcc'] = bcc
    
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return raw_message

# Google Drive Tools
@mcp.tool()
def drive_search(query: str, limit: int = 10) -> Dict[str, Any]:
    """Search for files in Google Drive"""
    try:
        logger.info(f"Searching Drive for: {query}")
        
        service = workspace_client.get_service('drive', 'v3')
        
        # Build search query
        search_query = f"name contains '{query}' or fullText contains '{query}'"
        
        results = service.files().list(
            q=search_query,
            pageSize=limit,
            fields="files(id, name, mimeType, modifiedTime, size, webViewLink)"
        ).execute()
        
        files = results.get('files', [])
        
        logger.info(f"Found {len(files)} files")
        
        return {
            "success": True,
            "files": files,
            "count": len(files)
        }
        
    except Exception as e:
        logger.error(f"Drive search error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
def drive_read_file(file_id: str) -> Dict[str, Any]:
    """Read the content of a file from Google Drive"""
    try:
        logger.info(f"Reading Drive file: {file_id}")
        
        service = workspace_client.get_service('drive', 'v3')
        
        # Get file metadata
        file_metadata = service.files().get(fileId=file_id).execute()
        mime_type = file_metadata.get('mimeType', '')
        
        # Handle different file types
        if 'google-apps.document' in mime_type:
            # Export Google Docs as plain text
            request = service.files().export_media(fileId=file_id, mimeType='text/plain')
        elif 'google-apps.spreadsheet' in mime_type:
            # Export Google Sheets as CSV
            request = service.files().export_media(fileId=file_id, mimeType='text/csv')
        elif 'google-apps.presentation' in mime_type:
            # Export Google Slides as plain text
            request = service.files().export_media(fileId=file_id, mimeType='text/plain')
        else:
            # Download regular files
            request = service.files().get_media(fileId=file_id)
        
        file_content = io.BytesIO()
        downloader = MediaIoBaseDownload(file_content, request)
        
        done = False
        while done is False:
            status, done = downloader.next_chunk()
        
        content = file_content.getvalue().decode('utf-8', errors='ignore')
        
        logger.info(f"Successfully read file: {file_metadata.get('name', 'Unknown')}")
        
        return {
            "success": True,
            "file_name": file_metadata.get('name', 'Unknown'),
            "mime_type": mime_type,
            "content": content[:10000],  # Limit content to 10KB
            "size": len(content)
        }
        
    except Exception as e:
        logger.error(f"Drive read file error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
def drive_create_file(name: str, content: str, mime_type: str = "text/plain") -> Dict[str, Any]:
    """Create a new file in Google Drive"""
    try:
        logger.info(f"Creating Drive file: {name}")
        
        service = workspace_client.get_service('drive', 'v3')
        
        # Create file metadata
        file_metadata = {
            'name': name
        }
        
        # Create media upload
        media = MediaIoBaseUpload(
            io.BytesIO(content.encode('utf-8')),
            mimetype=mime_type,
            resumable=True
        )
        
        # Create the file
        file = service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, name, webViewLink'
        ).execute()
        
        logger.info(f"Successfully created file: {file.get('name')}")
        
        return {
            "success": True,
            "file_id": file.get('id'),
            "file_name": file.get('name'),
            "web_view_link": file.get('webViewLink')
        }
        
    except Exception as e:
        logger.error(f"Drive create file error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
def drive_share_file(file_id: str, email: str, role: str = "reader") -> Dict[str, Any]:
    """Share a Google Drive file with a user"""
    try:
        logger.info(f"Sharing Drive file {file_id} with {email}")
        
        service = workspace_client.get_service('drive', 'v3')
        
        # Create permission
        permission = {
            'type': 'user',
            'role': role,
            'emailAddress': email
        }
        
        # Add permission
        service.permissions().create(
            fileId=file_id,
            body=permission,
            sendNotificationEmail=True
        ).execute()
        
        logger.info(f"Successfully shared file with {email}")
        
        return {
            "success": True,
            "message": f"File shared with {email} as {role}"
        }
        
    except Exception as e:
        logger.error(f"Drive share file error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

# Gmail Tools
@mcp.tool()
def gmail_send_email(to: str, subject: str, body: str, cc: str = None, bcc: str = None) -> Dict[str, Any]:
    """Send an email via Gmail"""
    try:
        logger.info(f"Sending email to: {to}")
        
        service = workspace_client.get_service('gmail', 'v1')
        
        # Create message
        message = {
            'raw': create_email_message(to, subject, body, cc, bcc)
        }
        
        # Send message
        result = service.users().messages().send(userId='me', body=message).execute()
        
        logger.info(f"Email sent successfully. Message ID: {result.get('id')}")
        
        return {
            "success": True,
            "message_id": result.get('id'),
            "message": f"Email sent to {to}"
        }
        
    except Exception as e:
        logger.error(f"Gmail send email error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
def gmail_search_emails(query: str, limit: int = 10) -> Dict[str, Any]:
    """Search for emails in Gmail"""
    try:
        logger.info(f"Searching Gmail for: {query}")
        
        service = workspace_client.get_service('gmail', 'v1')
        
        # Search for messages
        results = service.users().messages().list(
            userId='me',
            q=query,
            maxResults=limit
        ).execute()
        
        messages = results.get('messages', [])
        
        # Get message details
        email_details = []
        for message in messages[:limit]:
            msg = service.users().messages().get(
                userId='me',
                id=message['id'],
                format='metadata',
                metadataHeaders=['From', 'To', 'Subject', 'Date']
            ).execute()
            
            headers = {h['name']: h['value'] for h in msg['payload'].get('headers', [])}
            
            email_details.append({
                'id': message['id'],
                'from': headers.get('From', ''),
                'to': headers.get('To', ''),
                'subject': headers.get('Subject', ''),
                'date': headers.get('Date', ''),
                'snippet': msg.get('snippet', '')
            })
        
        logger.info(f"Found {len(email_details)} emails")
        
        return {
            "success": True,
            "emails": email_details,
            "count": len(email_details)
        }
        
    except Exception as e:
        logger.error(f"Gmail search error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
def gmail_read_email(message_id: str) -> Dict[str, Any]:
    """Read the full content of an email"""
    try:
        logger.info(f"Reading email: {message_id}")
        
        service = workspace_client.get_service('gmail', 'v1')
        
        # Get full message
        message = service.users().messages().get(
            userId='me',
            id=message_id,
            format='full'
        ).execute()
        
        # Extract headers
        headers = {h['name']: h['value'] for h in message['payload'].get('headers', [])}
        
        # Extract body
        body = ""
        if 'parts' in message['payload']:
            for part in message['payload']['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
                    break
        else:
            if message['payload']['body'].get('data'):
                body = base64.urlsafe_b64decode(
                    message['payload']['body']['data']
                ).decode('utf-8')
        
        logger.info(f"Successfully read email from {headers.get('From', 'Unknown')}")
        
        return {
            "success": True,
            "from": headers.get('From', ''),
            "to": headers.get('To', ''),
            "subject": headers.get('Subject', ''),
            "date": headers.get('Date', ''),
            "body": body,
            "snippet": message.get('snippet', '')
        }
        
    except Exception as e:
        logger.error(f"Gmail read email error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

# Google Calendar Tools
@mcp.tool()
def calendar_list_events(days_ahead: int = 7) -> Dict[str, Any]:
    """List upcoming calendar events"""
    try:
        logger.info(f"Listing calendar events for next {days_ahead} days")
        
        service = workspace_client.get_service('calendar', 'v3')
        
        # Calculate time range
        now = datetime.utcnow()
        time_min = now.isoformat() + 'Z'
        time_max = (now + timedelta(days=days_ahead)).isoformat() + 'Z'
        
        # Get events
        events_result = service.events().list(
            calendarId='primary',
            timeMin=time_min,
            timeMax=time_max,
            maxResults=50,
            singleEvents=True,
            orderBy='startTime'
        ).execute()
        
        events = events_result.get('items', [])
        
        # Format events
        formatted_events = []
        for event in events:
            start = event['start'].get('dateTime', event['start'].get('date'))
            end = event['end'].get('dateTime', event['end'].get('date'))
            
            formatted_events.append({
                'id': event['id'],
                'summary': event.get('summary', 'No title'),
                'start': start,
                'end': end,
                'description': event.get('description', ''),
                'location': event.get('location', ''),
                'attendees': [att.get('email') for att in event.get('attendees', [])]
            })
        
        logger.info(f"Found {len(formatted_events)} events")
        
        return {
            "success": True,
            "events": formatted_events,
            "count": len(formatted_events)
        }
        
    except Exception as e:
        logger.error(f"Calendar list events error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
def calendar_create_event(title: str, start_time: str, end_time: str, description: str = "", attendees: List[str] = None) -> Dict[str, Any]:
    """Create a new calendar event"""
    try:
        logger.info(f"Creating calendar event: {title}")
        
        service = workspace_client.get_service('calendar', 'v3')
        
        # Create event object
        event = {
            'summary': title,
            'description': description,
            'start': {
                'dateTime': start_time,
                'timeZone': 'UTC',
            },
            'end': {
                'dateTime': end_time,
                'timeZone': 'UTC',
            },
        }
        
        # Add attendees if provided
        if attendees:
            event['attendees'] = [{'email': email} for email in attendees]
        
        # Create the event
        created_event = service.events().insert(
            calendarId='primary',
            body=event,
            sendUpdates='all'
        ).execute()
        
        logger.info(f"Successfully created event: {created_event.get('id')}")
        
        return {
            "success": True,
            "event_id": created_event.get('id'),
            "event_link": created_event.get('htmlLink'),
            "message": f"Event '{title}' created successfully"
        }
        
    except Exception as e:
        logger.error(f"Calendar create event error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
def calendar_check_availability(start_time: str, end_time: str, attendees: List[str] = None) -> Dict[str, Any]:
    """Check availability for a time slot"""
    try:
        logger.info(f"Checking availability from {start_time} to {end_time}")
        
        service = workspace_client.get_service('calendar', 'v3')
        
        # Prepare request
        calendars = ['primary']
        if attendees:
            calendars.extend(attendees)
        
        body = {
            'timeMin': start_time,
            'timeMax': end_time,
            'items': [{'id': cal} for cal in calendars]
        }
        
        # Check free/busy
        freebusy = service.freebusy().query(body=body).execute()
        
        # Analyze results
        availability = {}
        for calendar_id, busy_info in freebusy.get('calendars', {}).items():
            busy_times = busy_info.get('busy', [])
            availability[calendar_id] = {
                'available': len(busy_times) == 0,
                'busy_periods': busy_times
            }
        
        logger.info(f"Availability check completed for {len(calendars)} calendars")
        
        return {
            "success": True,
            "availability": availability,
            "time_slot": f"{start_time} to {end_time}"
        }
        
    except Exception as e:
        logger.error(f"Calendar availability error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

# Main execution
if __name__ == "__main__":
    try:
        logger.info("Starting Google Workspace MCP Server...")
        logger.info(f"User ID: {workspace_client.user_id}")
        
        # Run the MCP server
        mcp.run()
        
    except KeyboardInterrupt:
        logger.info("MCP Server stopped by user")
    except Exception as e:
        logger.error(f"MCP Server error: {e}")
        sys.exit(1)