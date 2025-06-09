#!/usr/bin/env node

const https = require('https');

function checkRulesets() {
  const apiKey = process.env.GTI_APIKEY;
  
  if (!apiKey) {
    console.log('❌ Please set GTI_APIKEY environment variable');
    console.log('Usage: GTI_APIKEY="your-key" node check-rulesets.js');
    process.exit(1);
  }
  
  console.log('🔍 Checking your VirusTotal hunting rulesets...\n');
  
  const options = {
    hostname: 'www.virustotal.com',
    port: 443,
    path: '/api/v3/intelligence/hunting_rulesets?limit=20',
    method: 'GET',
    headers: {
      'x-apikey': apiKey
    }
  };
  
  const req = https.request(options, (res) => {
    let data = '';
    
    res.on('data', (chunk) => {
      data += chunk;
    });
    
    res.on('end', () => {
      if (res.statusCode === 200) {
        try {
          const response = JSON.parse(data);
          console.log(`✅ Found ${response.data.length} hunting rulesets in your account:\n`);
          
          response.data.forEach((ruleset, index) => {
            const attrs = ruleset.attributes;
            const createdDate = new Date(attrs.creation_date * 1000);
            const modifiedDate = new Date(attrs.modification_date * 1000);
            
            console.log(`${index + 1}. 📋 ${attrs.name}`);
            console.log(`   🆔 ID: ${ruleset.id}`);
            console.log(`   🔄 Status: ${attrs.enabled ? '✅ Enabled' : '❌ Disabled'}`);
            console.log(`   📅 Created: ${createdDate.toLocaleString()}`);
            console.log(`   ✏️  Modified: ${modifiedDate.toLocaleString()}`);
            console.log(`   📊 Rules: ${attrs.number_of_rules || 'N/A'} rule(s)`);
            console.log(`   🎯 Limit: ${attrs.limit || 'Default'} matches/day`);
            
            // Show first few lines of rules if available
            if (attrs.rules) {
              const ruleLines = attrs.rules.split('\n').slice(0, 3);
              console.log(`   📝 Rules preview:`);
              ruleLines.forEach(line => {
                if (line.trim()) console.log(`      ${line.trim()}`);
              });
              if (attrs.rules.split('\n').length > 3) {
                console.log(`      ... (${attrs.rules.split('\n').length - 3} more lines)`);
              }
            }
            console.log('');
          });
          
          // Look for recently created rulesets (last 24 hours)
          const recentRulesets = response.data.filter(ruleset => {
            const created = new Date(ruleset.attributes.creation_date * 1000);
            const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
            return created > oneDayAgo;
          });
          
          if (recentRulesets.length > 0) {
            console.log(`🆕 ${recentRulesets.length} ruleset(s) created in the last 24 hours:`);
            recentRulesets.forEach(ruleset => {
              console.log(`   • ${ruleset.attributes.name} (${new Date(ruleset.attributes.creation_date * 1000).toLocaleString()})`);
            });
          }
          
        } catch (error) {
          console.log('❌ Error parsing response:', error.message);
          console.log('Raw response:', data);
        }
      } else if (res.statusCode === 401) {
        console.log('❌ Authentication failed - check your API key');
      } else if (res.statusCode === 403) {
        console.log('❌ Access denied - Livehunt requires premium privileges');
        console.log('   You need a premium VirusTotal account to use hunting rulesets');
      } else {
        console.log(`❌ API request failed with status ${res.statusCode}`);
        console.log('Response:', data);
      }
    });
  });
  
  req.on('error', (error) => {
    console.log('❌ Request error:', error.message);
  });
  
  req.setTimeout(10000, () => {
    console.log('❌ Request timeout');
    req.abort();
  });
  
  req.end();
}

checkRulesets();