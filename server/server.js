const express = require('express');
const cors = require('cors');
const session = require('express-session');
const { OAuth2Client } = require('google-auth-library');
const OpenAI = require('openai');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs').promises;
require('dotenv').config();

// Import models
const User = require('./models/User');
const Chat = require('./models/Chat');
const Message = require('./models/Message');
const AuthToken = require('./models/AuthToken');
const Attachment = require('./models/Attachment');

// Import services
const FileUploadService = require('./services/fileUpload');
const FileParser = require('./services/fileParser');

// Import middleware
const upload = require('./middleware/upload');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Google OAuth client
const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// Initialize OpenAI
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Store MCP processes per user
const mcpProcesses = new Map();

// Middleware
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

// MCP Toolkit Management
async function startMCPServer(userId) {
  try {
    console.log(`🚀 Starting MCP server for user ${userId}`);
    
    // Get user's authentication tokens
    const tokenData = await AuthToken.findByUserId(userId);
    if (!tokenData) {
      throw new Error('No authentication tokens found for user');
    }

    // Check if process already exists
    if (mcpProcesses.has(userId)) {
      console.log(`♻️ MCP server already running for user ${userId}`);
      return mcpProcesses.get(userId);
    }

    // Start MCP server with user's tokens as environment variables
    const mcpProcess = spawn('python', [path.join(__dirname, 'mcp_toolkit.py')], {
      env: {
        ...process.env,
        USER_ID: userId,
        GOOGLE_ACCESS_TOKEN: tokenData.access_token,
        GOOGLE_REFRESH_TOKEN: tokenData.refresh_token,
        GOOGLE_ID_TOKEN: tokenData.id_token,
        GOOGLE_TOKEN_EXPIRES_AT: tokenData.expires_at,
        GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
        GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET
      },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    mcpProcess.stdout.on('data', (data) => {
      console.log(`MCP[${userId}]:`, data.toString().trim());
    });

    mcpProcess.stderr.on('data', (data) => {
      console.error(`MCP[${userId}] Error:`, data.toString().trim());
    });

    mcpProcess.on('close', (code) => {
      console.log(`MCP server for user ${userId} exited with code ${code}`);
      mcpProcesses.delete(userId);
    });

    mcpProcess.on('error', (error) => {
      console.error(`Failed to start MCP server for user ${userId}:`, error);
      mcpProcesses.delete(userId);
    });

    // Store the process
    mcpProcesses.set(userId, mcpProcess);
    
    // Wait a moment for the server to start
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    console.log(`✅ MCP server started for user ${userId}`);
    return mcpProcess;
  } catch (error) {
    console.error(`❌ Failed to start MCP server for user ${userId}:`, error);
    throw error;
  }
}

async function stopMCPServer(userId) {
  const process = mcpProcesses.get(userId);
  if (process) {
    console.log(`🛑 Stopping MCP server for user ${userId}`);
    process.kill();
    mcpProcesses.delete(userId);
  }
}

async function restartMCPServer(userId) {
  await stopMCPServer(userId);
  return await startMCPServer(userId);
}

// Google OAuth Routes
app.get('/auth/google', (req, res) => {
  const authUrl = googleClient.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/drive',
      'https://www.googleapis.com/auth/gmail.modify',
      'https://www.googleapis.com/auth/calendar'
    ],
    prompt: 'consent'
  });
  res.redirect(authUrl);
});

app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query;
    
    if (!code) {
      return res.redirect('http://localhost:5173/login?error=no_code');
    }

    // Exchange code for tokens
    const { tokens } = await googleClient.getTokens(code);
    googleClient.setCredentials(tokens);

    // Get user info
    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const userInfo = await userInfoResponse.json();

    // Find or create user
    let user = await User.findByGoogleId(userInfo.id);
    if (!user) {
      user = await User.create({
        googleId: userInfo.id,
        email: userInfo.email,
        name: userInfo.name,
        picture: userInfo.picture
      });
    } else {
      // Update user info
      user = await User.update(user.id, {
        name: userInfo.name,
        picture: userInfo.picture
      });
    }

    // Store or update tokens
    const expiresAt = new Date(Date.now() + (tokens.expiry_date || 3600000));
    
    const existingToken = await AuthToken.findByUserId(user.id);
    if (existingToken) {
      await AuthToken.update(user.id, {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token || existingToken.refresh_token,
        id_token: tokens.id_token,
        expires_at: expiresAt.toISOString()
      });
    } else {
      await AuthToken.create({
        userId: user.id,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        idToken: tokens.id_token,
        expiresAt: expiresAt.toISOString()
      });
    }

    // Set session
    req.session.userId = user.id;
    req.session.user = user;

    // Start MCP server for this user
    try {
      await startMCPServer(user.id);
    } catch (error) {
      console.error('Failed to start MCP server:', error);
      // Continue anyway - user can still use basic chat
    }

    res.redirect('http://localhost:5173/chat');
  } catch (error) {
    console.error('OAuth callback error:', error);
    res.redirect('http://localhost:5173/login?error=oauth_failed');
  }
});

// Auth status route
app.get('/auth/user', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.json({ authenticated: false });
    }

    const user = await User.findById(req.session.userId);
    if (!user) {
      req.session.destroy();
      return res.json({ authenticated: false });
    }

    res.json({
      authenticated: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture
      }
    });
  } catch (error) {
    console.error('Auth check error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout route
app.post('/auth/logout', async (req, res) => {
  try {
    const userId = req.session.userId;
    
    // Stop MCP server for this user
    if (userId) {
      await stopMCPServer(userId);
    }
    
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
        return res.status(500).json({ error: 'Logout failed' });
      }
      res.json({ success: true });
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Chat routes
app.post('/api/chat', requireAuth, upload.array('attachments', 5), async (req, res) => {
  try {
    const { message, chatId, model = 'gpt-4', enabledTools = [] } = req.body;
    const userId = req.session.userId;
    const files = req.files || [];

    console.log(`💬 Chat request from user ${userId}`);
    console.log(`📝 Message: ${message}`);
    console.log(`🤖 Model: ${model}`);
    console.log(`🔧 Enabled tools: ${enabledTools}`);
    console.log(`📎 Attachments: ${files.length} files`);

    // Ensure MCP server is running for this user
    if (!mcpProcesses.has(userId)) {
      try {
        await startMCPServer(userId);
      } catch (error) {
        console.error('Failed to start MCP server:', error);
        // Continue without MCP tools
      }
    }

    // Handle file attachments
    let attachmentData = [];
    let fileContents = [];
    
    if (files.length > 0) {
      console.log(`📎 Processing ${files.length} attachments...`);
      
      for (const file of files) {
        try {
          // Upload file to storage
          const uploadResult = await FileUploadService.uploadFile(file, userId);
          
          // Parse file content
          const content = await FileParser.parseFile(
            uploadResult.storagePath,
            uploadResult.mimeType,
            uploadResult.originalName
          );
          
          attachmentData.push(uploadResult);
          fileContents.push(`File: ${uploadResult.originalName}\nContent: ${content}`);
          
          console.log(`✅ Processed attachment: ${uploadResult.originalName}`);
        } catch (error) {
          console.error(`❌ Failed to process attachment ${file.originalname}:`, error);
          fileContents.push(`File: ${file.originalname}\nError: Failed to process file - ${error.message}`);
        }
      }
    }

    // Create or get chat
    let chat;
    if (chatId && chatId !== 'new') {
      chat = await Chat.findById(chatId);
      if (!chat || chat.user_id !== userId) {
        return res.status(404).json({ error: 'Chat not found' });
      }
    } else {
      // Create new chat with a title based on the message
      const title = message.length > 50 ? message.substring(0, 50) + '...' : message;
      chat = await Chat.create(userId, title);
    }

    // Combine message with file contents
    let fullMessage = message;
    if (fileContents.length > 0) {
      fullMessage += '\n\nAttached files:\n' + fileContents.join('\n\n');
    }

    // Save user message
    const userMessage = await Message.create({
      chatId: chat.id,
      userId,
      role: 'user',
      content: message,
      model,
      attachments: attachmentData.map(att => att.filename)
    });

    // Save attachments to database
    for (const attachment of attachmentData) {
      await Attachment.create({
        messageId: userMessage.id,
        userId,
        filename: attachment.filename,
        originalName: attachment.originalName,
        mimeType: attachment.mimeType,
        fileSize: attachment.fileSize,
        storagePath: attachment.storagePath
      });
    }

    // Prepare messages for OpenAI
    const messages = [
      {
        role: 'system',
        content: `You are a helpful AI assistant with access to Google Workspace tools. You can help users with:
- Google Drive: Search, read, create, edit, and share files
- Gmail: Send emails, read messages, manage labels
- Google Calendar: Create events, check availability, manage schedules
- File Analysis: Analyze uploaded documents, images, and other files

Always be helpful, accurate, and professional. When using tools, explain what you're doing and provide clear results.`
      },
      {
        role: 'user',
        content: fullMessage
      }
    ];

    // Get available tools (fallback list if MCP server is not available)
    const availableTools = [
      {
        type: "function",
        function: {
          name: "drive_search",
          description: "Search for files in Google Drive",
          parameters: {
            type: "object",
            properties: {
              query: { type: "string", description: "Search query" },
              limit: { type: "integer", description: "Maximum number of results", default: 10 }
            },
            required: ["query"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "drive_read_file",
          description: "Read the content of a file from Google Drive",
          parameters: {
            type: "object",
            properties: {
              file_id: { type: "string", description: "Google Drive file ID" }
            },
            required: ["file_id"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "drive_create_file",
          description: "Create a new file in Google Drive",
          parameters: {
            type: "object",
            properties: {
              name: { type: "string", description: "File name" },
              content: { type: "string", description: "File content" },
              mime_type: { type: "string", description: "MIME type", default: "text/plain" }
            },
            required: ["name", "content"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "gmail_send_email",
          description: "Send an email via Gmail",
          parameters: {
            type: "object",
            properties: {
              to: { type: "string", description: "Recipient email address" },
              subject: { type: "string", description: "Email subject" },
              body: { type: "string", description: "Email body" }
            },
            required: ["to", "subject", "body"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "gmail_search_emails",
          description: "Search for emails in Gmail",
          parameters: {
            type: "object",
            properties: {
              query: { type: "string", description: "Search query" },
              limit: { type: "integer", description: "Maximum number of results", default: 10 }
            },
            required: ["query"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "calendar_create_event",
          description: "Create a new calendar event",
          parameters: {
            type: "object",
            properties: {
              title: { type: "string", description: "Event title" },
              start_time: { type: "string", description: "Start time (ISO format)" },
              end_time: { type: "string", description: "End time (ISO format)" },
              description: { type: "string", description: "Event description" },
              attendees: { type: "array", items: { type: "string" }, description: "Attendee email addresses" }
            },
            required: ["title", "start_time", "end_time"]
          }
        }
      },
      {
        type: "function",
        function: {
          name: "calendar_list_events",
          description: "List upcoming calendar events",
          parameters: {
            type: "object",
            properties: {
              days_ahead: { type: "integer", description: "Number of days to look ahead", default: 7 }
            }
          }
        }
      }
    ];

    // Filter tools based on enabled tools
    const enabledToolsArray = Array.isArray(enabledTools) ? enabledTools : JSON.parse(enabledTools || '[]');
    const filteredTools = enabledToolsArray.length > 0 
      ? availableTools.filter(tool => enabledToolsArray.includes(tool.function.name))
      : availableTools;

    console.log(`🔧 Using ${filteredTools.length} tools`);

    // Call OpenAI with function calling
    const completion = await openai.chat.completions.create({
      model,
      messages,
      tools: filteredTools,
      tool_choice: 'auto',
      temperature: 0.7,
    });

    let response = completion.choices[0].message.content;
    let toolsUsed = [];

    // Handle function calls
    if (completion.choices[0].message.tool_calls) {
      console.log(`🔧 Processing ${completion.choices[0].message.tool_calls.length} tool calls`);
      
      for (const toolCall of completion.choices[0].message.tool_calls) {
        const functionName = toolCall.function.name;
        const functionArgs = JSON.parse(toolCall.function.arguments);
        
        console.log(`🔧 Calling tool: ${functionName} with args:`, functionArgs);
        toolsUsed.push(functionName);

        try {
          // Execute tool via MCP server
          const toolResult = await executeMCPTool(userId, functionName, functionArgs);
          
          // Add tool result to conversation
          messages.push({
            role: 'assistant',
            content: null,
            tool_calls: [toolCall]
          });
          
          messages.push({
            role: 'tool',
            tool_call_id: toolCall.id,
            content: JSON.stringify(toolResult)
          });
          
        } catch (error) {
          console.error(`❌ Tool execution failed for ${functionName}:`, error);
          messages.push({
            role: 'tool',
            tool_call_id: toolCall.id,
            content: JSON.stringify({ error: error.message })
          });
        }
      }

      // Get final response with tool results
      const finalCompletion = await openai.chat.completions.create({
        model,
        messages,
        temperature: 0.7,
      });

      response = finalCompletion.choices[0].message.content;
    }

    // Save assistant message
    await Message.create({
      chatId: chat.id,
      userId,
      role: 'assistant',
      content: response,
      model,
      toolsUsed
    });

    // Update chat timestamp
    await Chat.update(chat.id, { updated_at: new Date().toISOString() });

    console.log(`✅ Chat response generated successfully`);

    res.json({
      response,
      chatId: chat.id,
      model,
      toolsUsed
    });

  } catch (error) {
    console.error('❌ Chat error:', error);
    res.status(500).json({ 
      error: 'Failed to process chat message',
      details: error.message 
    });
  }
});

// Execute MCP tool
async function executeMCPTool(userId, functionName, functionArgs) {
  return new Promise((resolve, reject) => {
    const mcpProcess = mcpProcesses.get(userId);
    
    if (!mcpProcess) {
      reject(new Error('MCP server not available for user'));
      return;
    }

    const request = {
      method: 'tools/call',
      params: {
        name: functionName,
        arguments: functionArgs
      }
    };

    // Send request to MCP server
    mcpProcess.stdin.write(JSON.stringify(request) + '\n');

    // Listen for response
    const timeout = setTimeout(() => {
      reject(new Error('Tool execution timeout'));
    }, 30000); // 30 second timeout

    const onData = (data) => {
      try {
        const response = JSON.parse(data.toString().trim());
        clearTimeout(timeout);
        mcpProcess.stdout.removeListener('data', onData);
        
        if (response.error) {
          reject(new Error(response.error.message || 'Tool execution failed'));
        } else {
          resolve(response.result);
        }
      } catch (error) {
        // Ignore parsing errors, might be partial data
      }
    };

    mcpProcess.stdout.on('data', onData);
  });
}

// Get chat
app.get('/api/chat/:chatId', requireAuth, async (req, res) => {
  try {
    const { chatId } = req.params;
    const userId = req.session.userId;

    const chat = await Chat.getWithMessages(chatId, userId);
    if (!chat) {
      return res.status(404).json({ error: 'Chat not found' });
    }

    res.json(chat);
  } catch (error) {
    console.error('Get chat error:', error);
    res.status(500).json({ error: 'Failed to get chat' });
  }
});

// Get user chats
app.get('/api/chats/:userId', requireAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Ensure user can only access their own chats
    if (userId !== req.session.userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const chats = await Chat.findByUserId(userId);
    res.json({ chats });
  } catch (error) {
    console.error('Get chats error:', error);
    res.status(500).json({ error: 'Failed to get chats' });
  }
});

// Delete chat
app.delete('/api/chat/:chatId', requireAuth, async (req, res) => {
  try {
    const { chatId } = req.params;
    const userId = req.session.userId;

    const chat = await Chat.findById(chatId);
    if (!chat || chat.user_id !== userId) {
      return res.status(404).json({ error: 'Chat not found' });
    }

    await Chat.delete(chatId);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete chat error:', error);
    res.status(500).json({ error: 'Failed to delete chat' });
  }
});

// Get available tools
app.get('/api/tools', requireAuth, async (req, res) => {
  try {
    // Return the same tools list as used in chat
    const tools = [
      {
        function: {
          name: "drive_search",
          description: "Search for files in Google Drive"
        }
      },
      {
        function: {
          name: "drive_read_file",
          description: "Read the content of a file from Google Drive"
        }
      },
      {
        function: {
          name: "drive_create_file",
          description: "Create a new file in Google Drive"
        }
      },
      {
        function: {
          name: "gmail_send_email",
          description: "Send an email via Gmail"
        }
      },
      {
        function: {
          name: "gmail_search_emails",
          description: "Search for emails in Gmail"
        }
      },
      {
        function: {
          name: "calendar_create_event",
          description: "Create a new calendar event"
        }
      },
      {
        function: {
          name: "calendar_list_events",
          description: "List upcoming calendar events"
        }
      }
    ];

    res.json({ tools });
  } catch (error) {
    console.error('Get tools error:', error);
    res.status(500).json({ error: 'Failed to get tools' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  const userId = req.session?.userId;
  const mcpStatus = userId ? mcpProcesses.has(userId) : false;
  
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    mcp_server_running: mcpStatus,
    active_mcp_processes: mcpProcesses.size
  });
});

// MCP server management
app.post('/api/mcp/restart', requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    await restartMCPServer(userId);
    res.json({ success: true, message: 'MCP server restarted' });
  } catch (error) {
    console.error('MCP restart error:', error);
    res.status(500).json({ error: 'Failed to restart MCP server' });
  }
});

// Attachment download
app.get('/api/attachments/:attachmentId/download', requireAuth, async (req, res) => {
  try {
    const { attachmentId } = req.params;
    const userId = req.session.userId;

    const attachment = await Attachment.findById(attachmentId);
    if (!attachment || attachment.user_id !== userId) {
      return res.status(404).json({ error: 'Attachment not found' });
    }

    const signedUrl = await Attachment.getSignedUrl(attachment.storage_path);
    res.redirect(signedUrl);
  } catch (error) {
    console.error('Attachment download error:', error);
    res.status(500).json({ error: 'Failed to download attachment' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🛑 Shutting down server...');
  
  // Stop all MCP processes
  for (const [userId, process] of mcpProcesses) {
    console.log(`🛑 Stopping MCP server for user ${userId}`);
    process.kill();
  }
  
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('🛑 Shutting down server...');
  
  // Stop all MCP processes
  for (const [userId, process] of mcpProcesses) {
    console.log(`🛑 Stopping MCP server for user ${userId}`);
    process.kill();
  }
  
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Frontend: http://localhost:5173`);
  console.log(`🔗 Google OAuth: http://localhost:${PORT}/auth/google`);
});