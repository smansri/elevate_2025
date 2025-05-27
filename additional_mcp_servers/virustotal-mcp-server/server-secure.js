#!/usr/bin/env node

/**
 * VirusTotal MCP Server - Security Hardened Version
 * 
 * Implements secure coding practices:
 * - Input validation and sanitization
 * - Rate limiting and request timeouts
 * - Error handling without information disclosure
 * - Logging and monitoring capabilities
 * - Resource limits and DoS protection
 * 
 * Usage: VIRUSTOTAL_API_KEY="your-key" node server-secure.js
 */

const readline = require('readline');
const https = require('https');

class SecureVirusTotalMCPServer {
  constructor() {
    // Security: Validate API key exists and has minimum length
    this.apiKey = this.validateApiKey(process.env.VIRUSTOTAL_API_KEY);
    
    // Security: Rate limiting - max requests per minute
    this.requestCount = 0;
    this.requestWindow = Date.now();
    this.maxRequestsPerMinute = 60;
    
    // Security: Request size limits
    this.maxRequestSize = 1024 * 1024; // 1MB
    this.maxYARASize = 512 * 1024; // 512KB for YARA rules
    this.maxIOCsPerCollection = 1000;
    
    this.tools = this.initializeTools();
    this.setupReadline();
    
    // Security: Setup cleanup intervals
    setInterval(() => this.resetRateLimit(), 60000); // Reset every minute
  }

  validateApiKey(apiKey) {
    if (!apiKey) {
      throw new Error('VIRUSTOTAL_API_KEY environment variable not set');
    }
    
    // Security: Validate API key format (basic validation)
    if (typeof apiKey !== 'string' || apiKey.length < 32) {
      throw new Error('Invalid API key format');
    }
    
    // Security: Remove any whitespace/control characters
    return apiKey.trim().replace(/[^\w]/g, '');
  }

  initializeTools() {
    return [
      {
        name: "create_hunting_ruleset",
        description: "Create a new hunting ruleset in VirusTotal Livehunt with YARA rules",
        inputSchema: {
          type: "object",
          properties: {
            name: {
              type: "string",
              description: "Name of the hunting ruleset",
              minLength: 1,
              maxLength: 100,
              pattern: "^[a-zA-Z0-9_\\-\\s]+$"
            },
            rules: {
              type: "string", 
              description: "YARA rules content (VT module will be auto-imported)",
              minLength: 10,
              maxLength: 524288 // 512KB
            },
            enabled: {
              type: "boolean",
              description: "Whether the ruleset should be enabled (default: false for safety)",
              default: false
            }
          },
          required: ["name", "rules"],
          additionalProperties: false
        }
      },
      {
        name: "create_collection",
        description: "Create a new IOC collection in VirusTotal",
        inputSchema: {
          type: "object",
          properties: {
            name: {
              type: "string",
              description: "Name of the collection",
              minLength: 1,
              maxLength: 100,
              pattern: "^[a-zA-Z0-9_\\-\\s]+$"
            },
            description: {
              type: "string",
              description: "Description of the collection",
              maxLength: 500
            },
            domains: {
              type: "array",
              items: { 
                type: "string",
                pattern: "^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
                maxLength: 255
              },
              maxItems: 1000,
              description: "Domain names - e.g., ['malicious-site.com']"
            },
            urls: {
              type: "array", 
              items: { 
                type: "string",
                pattern: "^https?://[^\\s/$.?#].[^\\s]*$",
                maxLength: 2048
              },
              maxItems: 1000,
              description: "URLs - e.g., ['https://evil.com/malware.exe']"
            },
            ip_addresses: {
              type: "array",
              items: { 
                type: "string",
                pattern: "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                maxLength: 15
              },
              maxItems: 1000,
              description: "IPv4 addresses - e.g., ['192.168.1.100']"
            },
            file_hashes: {
              type: "array",
              items: { 
                type: "string",
                pattern: "^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$",
                maxLength: 64
              },
              maxItems: 1000,
              description: "File hashes (MD5/SHA1/SHA256)"
            }
          },
          required: ["name"],
          additionalProperties: false
        }
      }
    ];
  }

  setupReadline() {
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false
    });
    
    let inputBuffer = '';
    
    this.rl.on('line', (line) => {
      try {
        // Security: Check input size limits
        inputBuffer += line;
        if (inputBuffer.length > this.maxRequestSize) {
          this.sendError(-32600, "Request too large", null);
          inputBuffer = '';
          return;
        }
        
        const message = JSON.parse(line.trim());
        
        // Security: Validate message structure
        if (!this.validateMessage(message)) {
          this.sendError(-32600, "Invalid request", null);
          return;
        }
        
        this.handleMessage(message);
        inputBuffer = '';
      } catch (error) {
        // Security: Don't expose internal error details
        this.sendError(-32700, "Parse error", null);
        inputBuffer = '';
      }
    });
    
    process.stdin.resume();
  }

  validateMessage(message) {
    // Security: Validate JSON-RPC structure
    if (typeof message !== 'object' || message === null) return false;
    if (typeof message.jsonrpc !== 'string' || message.jsonrpc !== '2.0') return false;
    if (typeof message.method !== 'string' || message.method.length > 50) return false;
    if (message.id !== null && typeof message.id !== 'string' && typeof message.id !== 'number') return false;
    
    return true;
  }

  checkRateLimit() {
    const now = Date.now();
    
    // Reset counter if window has passed
    if (now - this.requestWindow > 60000) {
      this.requestCount = 0;
      this.requestWindow = now;
    }
    
    this.requestCount++;
    return this.requestCount <= this.maxRequestsPerMinute;
  }

  resetRateLimit() {
    this.requestCount = 0;
    this.requestWindow = Date.now();
  }

  async handleMessage(message) {
    // Security: Rate limiting
    if (!this.checkRateLimit()) {
      this.sendError(-32000, "Rate limit exceeded", message.id);
      return;
    }

    const { method, params, id } = message;
    
    try {
      switch (method) {
        case 'initialize':
          await this.handleInitialize(params, id);
          break;
        case 'tools/list':
          await this.handleToolsList(id);
          break;
        case 'tools/call':
          await this.handleToolCall(params, id);
          break;
        default:
          this.sendError(-32601, "Method not found", id);
      }
    } catch (error) {
      // Security: Log error but don't expose details
      console.error('Internal error:', error.message);
      this.sendError(-32603, "Internal error", id);
    }
  }

  async handleInitialize(params, id) {
    this.sendResponse({
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: {
        name: "virustotal-mcp-server-secure",
        version: "1.0.0"
      }
    }, id);
  }

  async handleToolsList(id) {
    this.sendResponse({ tools: this.tools }, id);
  }

  async handleToolCall(params, id) {
    // Security: Validate params structure
    if (!params || typeof params !== 'object') {
      this.sendError(-32602, "Invalid params", id);
      return;
    }

    const { name, arguments: args } = params;
    
    // Security: Validate tool name
    if (!name || typeof name !== 'string' || name.length > 50) {
      this.sendError(-32602, "Invalid tool name", id);
      return;
    }

    try {
      let result;
      switch (name) {
        case 'create_hunting_ruleset':
          result = await this.createHuntingRuleset(args);
          break;
        case 'create_collection':
          result = await this.createCollection(args);
          break;
        default:
          this.sendError(-32602, "Unknown tool", id);
          return;
      }
      
      const responseText = result.success 
        ? `✅ Success!\n\n${JSON.stringify(result.data, null, 2)}`
        : `❌ API Error (${result.statusCode})\n\n${JSON.stringify(result.error || result.data, null, 2)}`;
      
      this.sendResponse({
        content: [{ type: "text", text: responseText }]
      }, id);
    } catch (error) {
      console.error('Tool execution error:', error.message);
      this.sendError(-32603, "Tool execution failed", id);
    }
  }

  validateHuntingRulesetArgs(args) {
    if (!args || typeof args !== 'object') {
      throw new Error('Invalid arguments');
    }

    const { name, rules, enabled } = args;
    
    // Security: Validate name
    if (!name || typeof name !== 'string' || name.length > 100) {
      throw new Error('Invalid name');
    }
    
    if (!/^[a-zA-Z0-9_\-\s]+$/.test(name)) {
      throw new Error('Name contains invalid characters');
    }
    
    // Security: Validate rules
    if (!rules || typeof rules !== 'string' || rules.length > this.maxYARASize) {
      throw new Error('Invalid YARA rules');
    }
    
    // Security: Basic YARA validation
    if (!rules.includes('rule ') || !rules.includes('{') || !rules.includes('}')) {
      throw new Error('Invalid YARA syntax');
    }
    
    // Security: Validate enabled flag
    if (enabled !== undefined && typeof enabled !== 'boolean') {
      throw new Error('Invalid enabled flag');
    }
    
    return { name: name.trim(), rules: rules.trim(), enabled: enabled || false };
  }

  validateCollectionArgs(args) {
    if (!args || typeof args !== 'object') {
      throw new Error('Invalid arguments');
    }

    const { name, description, domains, urls, ip_addresses, file_hashes } = args;
    
    // Security: Validate name
    if (!name || typeof name !== 'string' || name.length > 100) {
      throw new Error('Invalid name');
    }
    
    if (!/^[a-zA-Z0-9_\-\s]+$/.test(name)) {
      throw new Error('Name contains invalid characters');
    }
    
    // Security: Validate description
    if (description && (typeof description !== 'string' || description.length > 500)) {
      throw new Error('Invalid description');
    }
    
    // Security: Validate IOC arrays
    const totalIOCs = (domains?.length || 0) + (urls?.length || 0) + (ip_addresses?.length || 0) + (file_hashes?.length || 0);
    if (totalIOCs > this.maxIOCsPerCollection) {
      throw new Error('Too many IOCs');
    }
    
    // Security: Validate domains
    if (domains && !Array.isArray(domains)) {
      throw new Error('Invalid domains');
    }
    
    if (domains) {
      domains.forEach(domain => {
        if (typeof domain !== 'string' || domain.length > 255 || !/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
          throw new Error('Invalid domain format');
        }
      });
    }
    
    // Security: Validate URLs
    if (urls && !Array.isArray(urls)) {
      throw new Error('Invalid URLs');
    }
    
    if (urls) {
      urls.forEach(url => {
        if (typeof url !== 'string' || url.length > 2048 || !/^https?:\/\/[^\s/$.?#].[^\s]*$/.test(url)) {
          throw new Error('Invalid URL format');
        }
      });
    }
    
    // Security: Validate IP addresses
    if (ip_addresses && !Array.isArray(ip_addresses)) {
      throw new Error('Invalid IP addresses');
    }
    
    if (ip_addresses) {
      ip_addresses.forEach(ip => {
        if (typeof ip !== 'string' || !/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)) {
          throw new Error('Invalid IP address format');
        }
      });
    }
    
    // Security: Validate file hashes
    if (file_hashes && !Array.isArray(file_hashes)) {
      throw new Error('Invalid file hashes');
    }
    
    if (file_hashes) {
      file_hashes.forEach(hash => {
        if (typeof hash !== 'string' || !/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(hash)) {
          throw new Error('Invalid file hash format');
        }
      });
    }
    
    return {
      name: name.trim(),
      description: description?.trim() || '',
      domains: domains || [],
      urls: urls || [],
      ip_addresses: ip_addresses || [],
      file_hashes: file_hashes || []
    };
  }

  async createHuntingRuleset(args) {
    const validatedArgs = this.validateHuntingRulesetArgs(args);
    const { name, rules, enabled } = validatedArgs;
    
    // Auto-import VT module for advanced features
    let processedRules = rules.includes('import "vt"') ? rules : `import "vt"\n${rules}`;
    
    // Add identification suffix
    const finalName = `${name}-Elevate2025`;
    
    const postData = JSON.stringify({
      data: {
        type: "hunting_ruleset",
        attributes: {
          name: finalName,
          rules: processedRules,
          enabled: enabled,
          match_object_type: "file",
          limit: 100
        }
      }
    });
    
    return this.makeSecureRequest('/api/v3/intelligence/hunting_rulesets', 'POST', postData);
  }

  async createCollection(args) {
    const validatedArgs = this.validateCollectionArgs(args);
    const { name, description, domains, urls, ip_addresses, file_hashes } = validatedArgs;
    
    // Validate that at least one IOC is provided
    const hasIOCs = domains.length > 0 || urls.length > 0 || ip_addresses.length > 0 || file_hashes.length > 0;
    
    if (!hasIOCs) {
      return {
        success: false,
        statusCode: 400,
        error: {
          code: "NoIOCsError",
          message: "No IOCs provided. Collections must contain at least one IOC."
        }
      };
    }
    
    // Add identification
    const finalName = `${name}-Elevate2025`;
    const finalDescription = description 
      ? `${description} (automatically created via cline / mcp)` 
      : 'automatically created via cline / mcp';
    
    // Build relationships
    const relationships = {};
    
    if (domains.length > 0) {
      relationships.domains = { data: domains.map(domain => ({ type: "domain", id: domain })) };
    }
    
    if (urls.length > 0) {
      relationships.urls = { data: urls.map(url => ({ type: "url", url: url })) };
    }
    
    if (ip_addresses.length > 0) {
      relationships.ip_addresses = { data: ip_addresses.map(ip => ({ type: "ip_address", id: ip })) };
    }
    
    if (file_hashes.length > 0) {
      relationships.files = { data: file_hashes.map(hash => ({ type: "file", id: hash })) };
    }
    
    const postData = JSON.stringify({
      data: {
        type: "collection",
        attributes: {
          name: finalName,
          description: finalDescription
        },
        relationships: relationships
      }
    });
    
    return this.makeSecureRequest('/api/v3/collections', 'POST', postData);
  }

  makeSecureRequest(path, method, postData = null) {
    return new Promise((resolve, reject) => {
      // Security: Validate path
      if (!path || typeof path !== 'string' || path.length > 200) {
        reject(new Error('Invalid request path'));
        return;
      }
      
      const options = {
        hostname: 'www.virustotal.com',
        port: 443,
        path: path,
        method: method,
        headers: {
          'x-apikey': this.apiKey,
          'Content-Type': 'application/json',
          'User-Agent': 'VirusTotal-MCP-Server/1.0.0'
        }
      };
      
      if (postData) {
        // Security: Validate post data size
        if (postData.length > this.maxRequestSize) {
          reject(new Error('Request payload too large'));
          return;
        