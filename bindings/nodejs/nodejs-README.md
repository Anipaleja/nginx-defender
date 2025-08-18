# nginx-defender for Node.js

A Node.js wrapper for the nginx-defender Web Application Firewall.

## Installation

```bash
npm install nginx-defender
```

## Requirements

- Node.js 14+
- nginx-defender service binary

## Quick Start

```javascript
const { NginxDefender } = require('nginx-defender');

async function main() {
    const defender = new NginxDefender();
    
    // Start the service
    await defender.start();
    
    // Check if IP should be blocked
    if (await defender.shouldBlock('192.168.1.100')) {
        console.log('IP should be blocked!');
    }
    
    // Get threat score
    const score = await defender.getThreatScore('192.168.1.100');
    console.log(`Threat score: ${score}`);
    
    // Monitor log files
    await defender.monitorLogFile('/var/log/nginx/access.log', 'combined');
    
    // Block IP manually
    await defender.blockIP('203.0.113.1', 30, 'Suspicious activity');
    
    // Clean up
    await defender.stop();
}

main().catch(console.error);
```

## Express Integration

```javascript
const express = require('express');
const { NginxDefender, expressMiddleware } = require('nginx-defender');

const app = express();
const defender = new NginxDefender();

// Start defender
defender.start().then(() => {
    console.log('nginx-defender started');
});

// Add middleware
app.use(expressMiddleware(defender));

app.get('/', (req, res) => {
    res.json({
        message: 'Protected by nginx-defender!',
        threatScore: req.threatScore
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

## Koa Integration

```javascript
const Koa = require('koa');
const { NginxDefender, koaMiddleware } = require('nginx-defender');

const app = new Koa();
const defender = new NginxDefender();

// Start defender
defender.start();

// Add middleware
app.use(koaMiddleware(defender));

app.use(async ctx => {
    ctx.body = {
        message: 'Protected by nginx-defender!',
        threatScore: ctx.threatScore
    };
});

app.listen(3000);
```

## Configuration

```javascript
const config = {
    logLevel: 'info',
    dryRun: false,
    webUI: true,
    webUIPort: 8080,
    metricsPort: 9090
};

const defender = new NginxDefender(config);
```

## Event Handling

```javascript
defender.on('started', () => {
    console.log('nginx-defender started');
});

defender.on('ipBlocked', (event) => {
    console.log(`IP blocked: ${event.ip} for ${event.duration} minutes`);
});

defender.on('ipUnblocked', (event) => {
    console.log(`IP unblocked: ${event.ip}`);
});

defender.on('error', (error) => {
    console.error('nginx-defender error:', error);
});
```

## TypeScript Support

```typescript
import { NginxDefender, expressMiddleware } from 'nginx-defender';

const defender: NginxDefender = new NginxDefender({
    logLevel: 'debug',
    webUIPort: 8081
});

await defender.start();
```

## API Reference

### Methods

- `start()` - Start the defender service
- `stop()` - Stop the defender service  
- `shouldBlock(ip)` - Check if IP should be blocked
- `getThreatScore(ip)` - Get threat score for IP
- `blockIP(ip, duration, reason)` - Block an IP address
- `unblockIP(ip)` - Unblock an IP address
- `monitorLogFile(path, format)` - Monitor a log file
- `getMetrics()` - Get system metrics

### Events

- `started` - Service started successfully
- `stopped` - Service stopped
- `ipBlocked` - IP was blocked
- `ipUnblocked` - IP was unblocked
- `error` - Error occurred
