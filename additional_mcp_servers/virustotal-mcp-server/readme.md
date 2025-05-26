# VirusTotal MCP Server

A Model Context Protocol (MCP) server that provides integration with VirusTotal API endpoints for creating hunting rulesets and collections.

## Features

- **Zero Dependencies**: Built using only Node.js built-in modules
- **Cross-Platform**: Works on macOS, Linux, and Windows
- **VirusTotal Integration**: 
  - Create hunting rulesets in VirusTotal Livehunt
  - Create collections in VirusTotal

## Prerequisites

- Node.js 18.0.0 or higher
- VirusTotal API key

## Setup

1. **Clone or download the project files**
2. **Get your VirusTotal API key**:
   - Sign up at [VirusTotal](https://www.virustotal.com/)
   - Go to your profile and copy your API key
3. **Set environment variable**:
   ```bash
   export VIRUSTOTAL_API_KEY="your-api-key-here"
   ```

## Usage

### Running the Server

```bash
# Set your API key and start the server
VIRUSTOTAL_API_KEY="your-api-key" node server.js
```

### Available Tools

#### 1. create_hunting_ruleset
Creates a new hunting ruleset in VirusTotal Livehunt.

**Parameters:**
- `name` (required): Name of the hunting ruleset
- `rules` (required): YARA rules content
- `enabled` (optional): Whether the ruleset should be enabled (default: true)

**Example:**
```json
{
  "name": "Malware Detection Rules",
  "rules": "rule suspicious_file { strings: $hex = { 4D 5A } condition: $hex }",
  "enabled": true
}
```

#### 2. create_collection
Creates a new collection in VirusTotal.

**Parameters:**
- `name` (required): Name of the collection
- `description` (optional): Description of the collection

**Example:**
```json
{
  "name": "Suspicious Files Collection",
  "description": "Collection of files flagged during investigation"
}
```

### Testing

Run the test suite to verify everything works:

```bash
# Test basic MCP protocol
node test.js

# Test API integration (requires valid API key)
VIRUSTOTAL_API_KEY="your-api-key" node api-test.js
```

## Integration with MCP Clients

This server works with any MCP-compatible client. For example, with Claude Desktop:

1. Add to your Claude Desktop configuration:
```json
{
  "mcpServers": {
    "virustotal": {
      "command": "node",
      "args": ["/path/to/your/server.js"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

2. Restart Claude Desktop
3. Use the tools in your conversations with Claude

## Error Handling

The server provides detailed error messages for common issues:
- Invalid API key: Returns 401 error with "Wrong API key" message
- Missing parameters: Validates required fields before making API calls
- Network issues: Handles connection timeouts and network errors
- API rate limits: Passes through VirusTotal's rate limiting responses

## Security Notes

- Never commit your API key to version control
- Use environment variables for API key storage
- The server only makes outbound HTTPS requests to VirusTotal
- No data persistence - all operations are stateless

## Troubleshooting

### Common Issues

1. **"VIRUSTOTAL_API_KEY environment variable not set"**
   - Make sure you've exported the environment variable
   - Check the variable name is exactly `VIRUSTOTAL_API_KEY`

2. **"Wrong API key" error**
   - Verify your API key is correct
   - Check you have the right permissions for Livehunt (premium feature)

3. **Server not responding**
   - Ensure Node.js 18+ is installed
   - Check the server process is running
   - Verify stdin/stdout are properly connected

### Debug Mode

Run with debug output:
```bash
VIRUSTOTAL_API_KEY="your-key" node server.js 2>debug.log
```

This will log debug messages to `debug.log` while keeping the MCP protocol clean on stdout.

## API Reference

- [VirusTotal Livehunt API](https://docs.virustotal.com/reference/api-livehunt)
- [VirusTotal Collections API](https://docs.virustotal.com/reference/collections-create)
- [MCP Protocol Specification](https://modelcontextprotocol.io/docs/specification)

## License

MIT License - feel free to modify and distribute.