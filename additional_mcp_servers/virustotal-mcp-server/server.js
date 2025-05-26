#!/usr/bin/env node

const readline = require('readline');
const https = require('https');

class VirusTotalMCPServer {
  constructor() {
    this.apiKey = process.env.VIRUSTOTAL_API_KEY;
    this.tools = [
      {
        name: "create_hunting_ruleset",
        description: "Create a new hunting ruleset in VirusTotal Livehunt",
        inputSchema: {
          type: "object",
          properties: {
            name: {
              type: "string",
              description: "Name of the hunting ruleset"
            },
            rules: {
              type: "string", 
              description: "YARA rules content"
            },
            enabled: {
              type: "boolean",
              description: "Whether the ruleset should be enabled",
              default: true
            }
          },
          required: ["name", "rules"]
        }
      },
      {
        name: "create_collection",
        description: "Create a new collection in VirusTotal",
        inputSchema: {
          type: "object",
          properties: {
            name: {
              type: "string",
              description: "Name of the collection"
            },
            description: {
              type: "string",
              description: "Description of the collection"
            }
          },
          required: ["name"]
        }
      }
    ];
    
    this.setupReadline();
  }

  setupReadline() {
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false  // Important: disable terminal mode for piped input
    });
    
    this.rl.on('line', (line) => {
      try {
        const message = JSON.parse(line.trim());
        this.handleMessage(message);
      } catch (error) {
        console.error('Parse error:', error.message); // Debug to stderr
        this.sendError(-32700, "Parse error", null);
      }
    });
    
    // Keep process alive
    process.stdin.resume();
  }

  async handleMessage(message) {
    const { method, params, id } = message;
    
    console.error(`Handling method: ${method}`); // Debug output
    
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
      console.error('Handle error:', error); // Debug output
      this.sendError(-32603, "Internal error", id);
    }
  }

  async handleInitialize(params, id) {
    if (!this.apiKey) {
      this.sendError(-32602, "VIRUSTOTAL_API_KEY environment variable not set", id);
      return;
    }

    this.sendResponse({
      protocolVersion: "2024-11-05",
      capabilities: {
        tools: {}
      },
      serverInfo: {
        name: "virustotal-mcp-server",
        version: "1.0.0"
      }
    }, id);
  }

  async handleToolsList(id) {
    this.sendResponse({
      tools: this.tools
    }, id);
  }

  async handleToolCall(params, id) {
    const { name, arguments: args } = params;
    
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
          this.sendError(-32602, `Unknown tool: ${name}`, id);
          return;
      }
      
      // Format response based on success/failure
      let responseText;
      if (result.success) {
        responseText = `✅ Success!\n\n${JSON.stringify(result.data, null, 2)}`;
      } else {
        responseText = `❌ API Error (${result.statusCode})\n\n${JSON.stringify(result.error || result.data, null, 2)}`;
      }
      
      this.sendResponse({
        content: [
          {
            type: "text",
            text: responseText
          }
        ]
      }, id);
    } catch (error) {
      this.sendError(-32603, `Tool execution failed: ${error.message}`, id);
    }
  }

  async createHuntingRuleset(args) {
    const { name, rules, enabled = true } = args;
    
    // Ensure VT module import is included for advanced features
    let processedRules = rules;
    if (!rules.includes('import "vt"')) {
      processedRules = 'import "vt"\n' + rules;
    }
    
    // Append identification to rule name
    // REMOVE THIS LINE if you don't want the "-Elevate2025" suffix:
    const finalName = `${name}-Elevate2025`;
    
    // VirusTotal Livehunt API expects a specific JSON structure
    const postData = JSON.stringify({
      data: {
        type: "hunting_ruleset",
        attributes: {
          name: finalName, // CHANGE back to 'name' if you removed the suffix above
          rules: processedRules,
          enabled: enabled,
          match_object_type: "file",  // Required field - can be file, url, domain, ip
          limit: 100  // Optional - max matches per day
        }
      }
    });
    
    const options = {
      hostname: 'www.virustotal.com',
      port: 443,
      path: '/api/v3/intelligence/hunting_rulesets',
      method: 'POST',
      headers: {
        'x-apikey': this.apiKey,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    };
    
    return this.makeHTTPSRequest(options, postData);
  }

  async createCollection(args) {
    const { 
      name, 
      description = '', 
      domains = [], 
      urls = [], 
      ip_addresses = [], 
      file_hashes = [] 
    } = args;
    
    // Check if this is an empty collection (no IOCs provided)
    const hasIOCs = domains.length > 0 || urls.length > 0 || ip_addresses.length > 0 || file_hashes.length > 0;
    
    if (!hasIOCs) {
      // Return user-friendly error instead of trying to create empty collection
      return {
        success: false,
        statusCode: 400,
        error: {
          code: "NoIOCsError",
          message: "No IOCs provided. Collections must contain at least one IOC (domain, URL, IP address, or file hash)."
        }
      };
    }
    
    // Append identification to collection name and description
    // REMOVE THESE 2 LINES if you don't want the "-Elevate2025" suffix and auto-description:
    const finalName = `${name}-Elevate2025`;
    const finalDescription = description ? `${description} (automatically created via cline / mcp)` : 'automatically created via cline / mcp';
    
    // Build relationships object for IOCs
    const relationships = {};
    
    if (domains.length > 0) {
      relationships.domains = {
        data: domains.map(domain => ({
          type: "domain",
          id: domain
        }))
      };
    }
    
    if (urls.length > 0) {
      relationships.urls = {
        data: urls.map(url => ({
          type: "url",
          url: url
        }))
      };
    }
    
    if (ip_addresses.length > 0) {
      relationships.ip_addresses = {
        data: ip_addresses.map(ip => ({
          type: "ip_address",
          id: ip
        }))
      };
    }
    
    if (file_hashes.length > 0) {
      relationships.files = {
        data: file_hashes.map(hash => ({
          type: "file",
          id: hash
        }))
      };
    }
    
    // Create collection with IOCs using relationships approach
    const postData = JSON.stringify({
      data: {
        type: "collection",
        attributes: {
          name: finalName, // CHANGE back to 'name' if you removed the suffix above
          description: finalDescription // CHANGE back to 'description' if you removed the auto-description above
        },
        relationships: relationships
      }
    });
    
    const options = {
      hostname: 'www.virustotal.com',
      port: 443,
      path: '/api/v3/collections',
      method: 'POST',
      headers: {
        'x-apikey': this.apiKey,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    };
    
    return this.makeHTTPSRequest(options, postData);
  }

  makeHTTPSRequest(options, postData = null) {
    return new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let data = '';
        
        res.on('data', (chunk) => {
          data += chunk;
        });
        
        res.on('end', () => {
          try {
            const response = JSON.parse(data);
            
            if (res.statusCode >= 200 && res.statusCode < 300) {
              resolve({
                success: true,
                statusCode: res.statusCode,
                data: response
              });
            } else {
              resolve({
                success: false,
                statusCode: res.statusCode,
                error: response.error || response,
                data: response
              });
            }
          } catch (error) {
            reject(new Error(`Failed to parse response: ${error.message}`));
          }
        });
      });
      
      req.on('error', (error) => {
        reject(new Error(`Request failed: ${error.message}`));
      });
      
      if (postData) {
        req.write(postData);
      }
      
      req.end();
    });
  }

  sendResponse(result, id) {
    const response = {
      jsonrpc: "2.0",
      result,
      id
    };
    console.log(JSON.stringify(response));
  }

  sendError(code, message, id) {
    const response = {
      jsonrpc: "2.0",
      error: { code, message },
      id
    };
    console.log(JSON.stringify(response));
  }
}

// Start the server
const server = new VirusTotalMCPServer();

// Handle process termination
process.on('SIGINT', () => {
  process.exit(0);
});

process.on('SIGTERM', () => {
  process.exit(0);
});