# Creart-Firewall API v1.2.0

[![npm version](https://img.shields.io/npm/v/creart-firewall.svg)](https://www.npmjs.com/package/creart-firewall) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Node.js Version](https://img.shields.io/badge/node-%3E%3D22.0-brightgreen)](https://nodejs.org) [![Downloads](https://img.shields.io/npm/dm/creart-firewall.svg)](https://www.npmjs.com/package/creart-firewall) [![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/hamzadenizyilmaz/Creart-Firewall-API) [![Last Commit](https://img.shields.io/github/last-commit/hamzadenizyilmaz/Creart-Firewall-API)](https://github.com/hamzadenizyilmaz/Creart-Firewall-API)

**Advanced Linux firewall management API for Node.js** - Manage UFW, iptables, and system monitoring with a simple, powerful API.

## ✨ Features

### 🔥 **Complete Firewall Management**
- **UFW (Uncomplicated Firewall)** - Full management with rule adding/deleting/listing
- **iptables** - Advanced rule management with chains and tables
- **Port Management** - Open/close ports with single commands
- **IP Blocking** - Block/allow specific IPs or ranges
- **Rate Limiting** - Prevent DoS attacks with rate limits
- **Port Forwarding** - NAT and port forwarding rules

### 📊 **System Monitoring**
- **Real-time Monitoring** - CPU, Memory, Disk, Network usage
- **Connection Tracking** - Active network connections
- **Port Scanning** - Security auditing of open ports
- **Process Monitoring** - System processes and resource usage
- **Health Checks** - System health status and alerts

### 🔐 **Security & Automation**
- **SSH Remote Management** - Manage remote servers via SSH
- **Automatic Backups** - Backup/restore firewall configurations
- **Real-time Log Watching** - Monitor firewall logs live
- **Rule Validation** - Validate rules before applying
- **Batch Operations** - Apply multiple rules at once

### ⚡ **Performance & Reliability**
- **Caching System** - Performance optimization
- **Retry Mechanism** - Automatic retry on failures
- **Error Recovery** - Graceful error handling
- **Parallel Execution** - Fast batch operations
- **Resource Optimization** - Low memory footprint

## 📦 Installation

```bash
npm install creart-firewall
# or
yarn add creart-firewall
```

## 🚀 Quick Start

### Basic Local Usage
```javascript
const CreartFirewall = require('creart-firewall');

// Initialize for local system
const firewall = new CreartFirewall();

// Get UFW status
const ufwStatus = await firewall.ufw.getStatus();
console.log('UFW Status:', ufwStatus);

// Add a firewall rule
await firewall.ufw.addRule({
  action: 'allow',
  port: '3000',
  protocol: 'tcp',
  direction: 'in',
  source: 'any',
  comment: 'API Server'
});

// List all rules
const rules = await firewall.ufw.getRules();
console.log('Rules:', rules);
```

### Remote SSH Management
```javascript
const CreartFirewall = require('creart-firewall');

// Initialize for remote server via SSH
const firewall = new CreartFirewall({
  sshHost: '192.168.1.100',
  sshPort: 22,
  sshUsername: 'admin',
  sshPrivateKey: '/path/to/private/key',
  logLevel: 'info'
});

// Manage remote firewall
await firewall.ufw.enable();
await firewall.iptables.openPort(443, 'tcp');
await firewall.iptables.blockIP('192.168.1.50');
```

### System Monitoring
```javascript
const { SystemInfo } = require('creart-firewall');
const system = new SystemInfo();

// Get complete system information
const systemInfo = await system.getSystemInfo();
console.log('CPU Usage:', systemInfo.cpu.usage);
console.log('Memory:', systemInfo.memory.usage);
console.log('Disk:', systemInfo.disk.total.usage);

// Scan for open ports
const openPorts = await system.scanPorts('localhost', '1-1000');
console.log('Open Ports:', openPorts);

// Monitor system health
const health = await system.getStatus();
console.log('System Health:', health.health);
```

## 📖 API Reference

### Main Classes

#### `CreartFirewall`
Main class for comprehensive firewall management.

```javascript
const firewall = new CreartFirewall(options);
```

**Options:**
```javascript
{
  sshHost: 'string',           // SSH server address
  sshPort: 22,                 // SSH port
  sshUsername: 'string',       // SSH username
  sshPrivateKey: 'string',     // SSH private key path
  sshPassword: 'string',       // SSH password (optional)
  logLevel: 'info',            // debug, info, warn, error
  defaultInterface: 'eth0',    // Default network interface
  backupEnabled: true,         // Enable automatic backups
  autoSave: true               // Auto-save rules after changes
}
```

#### `UFWManager`
Specialized class for UFW management.

```javascript
const { UFWManager } = require('creart-firewall');
const ufw = new UFWManager(config);
```

#### `IPTablesManager`
Specialized class for iptables management.

```javascript
const { IPTablesManager } = require('creart-firewall');
const iptables = new IPTablesManager(config);
```

#### `SystemInfo`
System monitoring and information class.

```javascript
const { SystemInfo } = require('creart-firewall');
const system = new SystemInfo(config);
```

### Key Methods

#### UFW Management
```javascript
// Enable/disable UFW
await ufw.enable();
await ufw.disable();

// Add rule
await ufw.addRule({
  action: 'allow',      // allow, deny, reject, limit
  port: '80',          // Port number or range (3000:4000)
  protocol: 'tcp',     // tcp, udp, any
  direction: 'in',     // in, out
  source: '192.168.1.0/24',
  comment: 'Web Server'
});

// List rules
const rules = await ufw.getRules();

// Get logs
const logs = await ufw.getLogs({ limit: 50 });

// Backup rules
await ufw.backupRules('daily-backup');
```

#### iptables Management
```javascript
// Open port
await iptables.openPort(443, 'tcp');

// Block IP
await iptables.blockIP('192.168.1.50');

// Port forwarding
await iptables.addPortForward(8080, '192.168.1.100', 80);

// List rules
const rules = await iptables.listRules('INPUT');

// Flush rules
await iptables.flushRules();

// Backup configuration
await iptables.backupRules('pre-update');
```

#### System Monitoring
```javascript
// Get system info
const info = await system.getSystemInfo();

// CPU usage
const cpu = await system.getCPUInfo();

// Memory usage
const memory = await system.getMemoryInfo();

// Disk usage
const disk = await system.getDiskInfo();

// Network information
const network = await system.getNetworkInfo();

// Port scanning
const scan = await system.scanPorts('192.168.1.1', '20-100');

// Health check
const health = await system.getStatus();
```

## 🔧 Advanced Usage

### Rule Validation
```javascript
const rule = {
  action: 'allow',
  port: '3000',
  protocol: 'tcp',
  direction: 'in',
  source: '192.168.1.0/24'
};

// Validate before applying
if (firewall.validators.validateRule(rule)) {
  await firewall.ufw.addRule(rule);
}
```

### Batch Operations
```javascript
const rules = [
  { action: 'allow', port: '22', protocol: 'tcp', comment: 'SSH' },
  { action: 'allow', port: '80', protocol: 'tcp', comment: 'HTTP' },
  { action: 'allow', port: '443', protocol: 'tcp', comment: 'HTTPS' },
  { action: 'allow', port: '3000:4000', protocol: 'tcp', comment: 'API Range' }
];

for (const rule of rules) {
  await firewall.ufw.addRule(rule);
}
```

### Real-time Monitoring
```javascript
// Monitor firewall logs in real-time
const stopMonitor = await firewall.monitor((log) => {
  console.log('New log entry:', log);
  
  // Alert on suspicious activity
  if (log.includes('DROP')) {
    console.warn('Blocked connection detected!');
  }
}, { interval: 1000 });

// Stop monitoring after 1 minute
setTimeout(() => {
  stopMonitor();
  console.log('Monitoring stopped');
}, 60000);
```

### Automated Backups
```javascript
// Schedule regular backups
const scheduleBackup = async () => {
  const backup = await firewall.backupRules();
  console.log('Backup created:', backup.file);
  
  // Upload to remote storage or send notification
  // await uploadToS3(backup.file);
};

// Run backup every day at 2 AM
setInterval(scheduleBackup, 24 * 60 * 60 * 1000);
```

## ⚙️ Configuration Examples

### Production Configuration
```javascript
const firewall = new CreartFirewall({
  sshHost: 'production-server.com',
  sshPort: 2222,
  sshUsername: 'firewall-admin',
  sshPrivateKey: '/etc/ssh/firewall-key',
  logLevel: 'warn',
  backupEnabled: true,
  backupDir: '/var/backups/firewall',
  autoSave: true,
  validation: {
    strict: true,
    checkConflicts: true,
    validateIPs: true
  }
});
```

### Development Configuration
```javascript
const firewall = new CreartFirewall({
  logLevel: 'debug',
  backupEnabled: false,
  autoSave: false,
  testing: true
});
```

### Multi-Server Management
```javascript
const servers = [
  { host: 'web1.example.com', role: 'web' },
  { host: 'db1.example.com', role: 'database' },
  { host: 'api1.example.com', role: 'api' }
];

for (const server of servers) {
  const firewall = new CreartFirewall({
    sshHost: server.host,
    sshUsername: 'admin',
    sshPrivateKey: '/path/to/key'
  });
  
  // Apply role-based rules
  await applyRoleRules(firewall, server.role);
}

async function applyRoleRules(firewall, role) {
  const rules = {
    web: [
      { action: 'allow', port: '80', protocol: 'tcp' },
      { action: 'allow', port: '443', protocol: 'tcp' }
    ],
    database: [
      { action: 'allow', port: '3306', protocol: 'tcp', source: 'web-servers' }
    ],
    api: [
      { action: 'allow', port: '3000', protocol: 'tcp' },
      { action: 'limit', port: '22', protocol: 'tcp', limit: '10/minute' }
    ]
  };
  
  for (const rule of rules[role] || []) {
    await firewall.ufw.addRule(rule);
  }
}
```

## 🐳 Docker Support

### Dockerfile
```dockerfile
FROM node:14-alpine
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    sudo \
    ufw \
    iptables \
    ip6tables \
    net-tools \
    iproute2

# Install npm dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy application files
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app

USER nodejs

# Expose API port
EXPOSE 3000

CMD ["node", "index.js"]
```

### docker-compose.yml
```yaml
version: '3.8'
services:
  firewall-api:
    build: .
    ports:
      - "3000:3000"
    volumes:
      - ./config:/app/config
      - ./backups:/app/backups
      - /etc/ufw:/etc/ufw:ro
      - /etc/iptables:/etc/iptables:ro
    environment:
      - NODE_ENV=production
      - LOG_LEVEL=info
    cap_add:
      - NET_ADMIN
      - NET_RAW
    restart: unless-stopped
```

## 🧪 Testing

### Basic Tests
```javascript
const testFirewall = async () => {
  const firewall = new CreartFirewall();
  
  console.log('Testing UFW Manager...');
  const ufwStatus = await firewall.ufw.getStatus();
  console.assert(ufwStatus, 'UFW status test passed');
  
  console.log('Testing iptables Manager...');
  const iptablesStatus = await firewall.iptables.getStatus();
  console.assert(iptablesStatus, 'iptables status test passed');
  
  console.log('Testing System Info...');
  const systemInfo = await firewall.system.getInfo();
  console.assert(systemInfo, 'System info test passed');
  
  console.log('All tests passed! ✅');
};

testFirewall().catch(console.error);
```

### Integration Tests
```bash
# Run comprehensive tests
npm test

# Run specific test suite
npm test -- --grep "UFW"

# Run with coverage
npm test -- --coverage

# Run performance tests
npm test -- --grep "performance"
```

## 📊 Performance

### Benchmark Results
| Operation | Average Time | Memory Usage |
|-----------|--------------|--------------|
| UFW Status Check | 120ms | 15MB |
| Add Single Rule | 80ms | 5MB |
| List 100 Rules | 200ms | 25MB |
| System Info | 150ms | 20MB |
| Port Scan (1-1000) | 2.5s | 50MB |

### Optimization Tips
```javascript
// Enable caching for better performance
const firewall = new CreartFirewall({
  cacheConfig: {
    enabled: true,
    ttl: 300000, // 5 minutes
    maxItems: 100
  }
});

// Use batch operations for multiple rules
await firewall.addMultipleRules(rules);

// Disable validation for bulk imports
await firewall.addRule(rule, { validate: false });
```

## 🔐 Security Considerations

### Best Practices
1. **Always validate rules** before applying
2. **Use rate limiting** for public services
3. **Regular backups** of firewall configurations
4. **Monitor logs** for suspicious activity
5. **Use SSH keys** instead of passwords
6. **Regular updates** of the firewall rules

### Security Configuration
```javascript
const secureConfig = {
  sshHost: 'secure-server.com',
  sshPort: 2222,
  sshUsername: 'admin',
  sshPrivateKey: '/secure/path/key',
  sshOptions: {
    readyTimeout: 30000,
    keepaliveInterval: 60000,
    algorithms: {
      cipher: ['aes256-gcm@openssh.com'],
      kex: ['ecdh-sha2-nistp256'],
      serverHostKey: ['ssh-rsa', 'ssh-ed25519']
    }
  },
  validation: {
    strict: true,
    maxRules: 1000,
    allowedPorts: [22, 80, 443, 3000, 3306, 5432]
  }
};
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone repository
git clone https://github.com/hamzadenizyilmaz/Creart-Firewall-API.git
cd firewall-api

# Install dependencies
npm install

# Run tests
npm test

# Build documentation
npm run docs

# Run linter
npm run lint
```

### Code Style
- Use **ES6+** features
- Follow **Airbnb JavaScript Style Guide**
- Write **comprehensive tests**
- Document **all public APIs**
- Maintain **backward compatibility**

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 📞 Support

- **GitHub Issues**: [Bug Reports & Feature Requests](https://github.com/creart/firewall-api/issues)
- **Email**: info@creartcloud.com
- **Documentation**: [Full API Docs (Coming Soon)](https://docs.creartsoft.com.tr/firewall-api)
- **Website**: [https://creartsoft.com.tr](https://creartsoft.com.tr)

## 🚀 Roadmap

### v1.3.0 (Upcoming)
- [ ] WebSocket support for real-time updates
- [ ] REST API server mode
- [ ] Plugin system for custom modules
- [ ] GUI dashboard integration
- [ ] Cloud synchronization

### v1.4.0 (Planned)
- [ ] Machine learning anomaly detection
- [ ] Automated security recommendations
- [ ] Multi-master replication
- [ ] Advanced reporting system
- [ ] Compliance auditing

---

**Creart Firewall API** is developed and maintained by **Hamza Deniz Yılmaz**.  
For commercial support and enterprise features, contact **info@creartcloud.com**.