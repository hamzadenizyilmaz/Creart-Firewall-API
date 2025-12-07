const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const os = require('os');

const execPromise = util.promisify(exec);

class Utils {
    constructor(config = {}) {
        this.config = {
            debug: config.debug || false,
            logFile: config.logFile || '/var/log/creart-firewall.log',
            ...config
        };
    }

    generateRandomString(length = 32) {
        return crypto.randomBytes(Math.ceil(length / 2))
            .toString('hex')
            .slice(0, length);
    }

    hashData(data, algorithm = 'sha256') {
        return crypto.createHash(algorithm)
            .update(data)
            .digest('hex');
    }

    async getFileHash(filePath, algorithm = 'sha256') {
        return new Promise((resolve, reject) => {
            const hash = crypto.createHash(algorithm);
            const stream = fs.createReadStream(filePath);

            stream.on('data', (data) => hash.update(data));
            stream.on('end', () => resolve(hash.digest('hex')));
            stream.on('error', reject);
        });
    }

    isValidIP(ip) {
        const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    }

    isValidCIDR(cidr) {
        const cidrRegex = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(3[0-2]|[12]?[0-9])$/;
        return cidrRegex.test(cidr);
    }

    isValidPort(port) {
        const portNum = parseInt(port);
        return !isNaN(portNum) && portNum >= 1 && portNum <= 65535;
    }

    isValidPortRange(range) {
        if (range.includes('-')) {
            const [start, end] = range.split('-').map(Number);
            return this.isValidPort(start) && this.isValidPort(end) && start <= end;
        } else if (range.includes(',')) {
            return range.split(',').every(port => this.isValidPort(port.trim()));
        }
        return this.isValidPort(range);
    }

    isValidMAC(mac) {
        const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
        return macRegex.test(mac);
    }

    isValidDomain(domain) {
        const domainRegex = /^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$/;
        return domainRegex.test(domain);
    }

    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    isValidJSON(str) {
        try {
            JSON.parse(str);
            return true;
        } catch (error) {
            return false;
        }
    }

    base64Encode(str) {
        return Buffer.from(str).toString('base64');
    }

    base64Decode(str) {
        return Buffer.from(str, 'base64').toString('utf8');
    }

    toCamelCase(str) {
        return str
            .replace(/([-_][a-z])/g, (group) =>
                group.toUpperCase().replace('-', '').replace('_', '')
            )
            .replace(/^./, (str) => str.toLowerCase());
    }

    toSnakeCase(str) {
        return str
            .replace(/\W+/g, ' ')
            .split(/ |\B(?=[A-Z])/)
            .map(word => word.toLowerCase())
            .join('_');
    }

    toKebabCase(str) {
        return str
            .replace(/\W+/g, ' ')
            .split(/ |\B(?=[A-Z])/)
            .map(word => word.toLowerCase())
            .join('-');
    }

    toTitleCase(str) {
        return str
            .toLowerCase()
            .split(' ')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    chunkArray(array, size) {
        const chunks = [];
        for (let i = 0; i < array.length; i += size) {
            chunks.push(array.slice(i, i + size));
        }
        return chunks;
    }

    deepClone(obj) {
        return JSON.parse(JSON.stringify(obj));
    }

    deepMerge(target, source) {
        const output = Object.assign({}, target);

        if (this.isObject(target) && this.isObject(source)) {
            Object.keys(source).forEach(key => {
                if (this.isObject(source[key])) {
                    if (!(key in target)) {
                        Object.assign(output, { [key]: source[key] });
                    } else {
                        output[key] = this.deepMerge(target[key], source[key]);
                    }
                } else {
                    Object.assign(output, { [key]: source[key] });
                }
            });
        }

        return output;
    }

    isObject(item) {
        return item && typeof item === 'object' && !Array.isArray(item);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async retry(fn, retries = 3, delay = 1000) {
        try {
            return await fn();
        } catch (error) {
            if (retries > 0) {
                await this.sleep(delay);
                return this.retry(fn, retries - 1, delay * 2);
            }
            throw error;
        }
    }

    async withTimeout(promise, ms, errorMessage = 'Timeout error') {
        let timeoutId;

        const timeoutPromise = new Promise((_, reject) => {
            timeoutId = setTimeout(() => {
                reject(new Error(errorMessage));
            }, ms);
        });

        try {
            const result = await Promise.race([promise, timeoutPromise]);
            clearTimeout(timeoutId);
            return result;
        } catch (error) {
            clearTimeout(timeoutId);
            throw error;
        }
    }

    async pathExists(path) {
        try {
            await fs.promises.access(path);
            return true;
        } catch (error) {
            return false;
        }
    }

    async ensureDir(dir) {
        if (!await this.pathExists(dir)) {
            await fs.promises.mkdir(dir, { recursive: true });
        }
        return dir;
    }

    async readFile(filePath, encoding = 'utf8') {
        return fs.promises.readFile(filePath, encoding);
    }

    async writeFile(filePath, data, encoding = 'utf8') {
        await this.ensureDir(path.dirname(filePath));
        return fs.promises.writeFile(filePath, data, encoding);
    }

    async appendFile(filePath, data, encoding = 'utf8') {
        await this.ensureDir(path.dirname(filePath));
        return fs.promises.appendFile(filePath, data, encoding);
    }

    async deleteFile(filePath) {
        if (await this.pathExists(filePath)) {
            await fs.promises.unlink(filePath);
            return true;
        }
        return false;
    }

    async listFiles(dir, pattern = null) {
        if (!await this.pathExists(dir)) {
            return [];
        }

        const files = await fs.promises.readdir(dir);

        if (pattern) {
            const regex = new RegExp(pattern);
            return files.filter(file => regex.test(file));
        }

        return files;
    }

    async log(level, message, data = null) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            level: level.toUpperCase(),
            message,
            data,
            pid: process.pid
        };

        if (this.config.debug || level === 'error') {
            console.log(`[${timestamp}] ${level.toUpperCase()}: ${message}`);
            if (data) {
                console.log('Data:', data);
            }
        }

        try {
            await this.appendFile(
                this.config.logFile,
                JSON.stringify(logEntry) + '\n'
            );
        } catch (error) {
            console.error('Log write error:', error);
        }

        return logEntry;
    }

    async error(message, error = null) {
        return this.log('error', message, {
            error: error?.message || error,
            stack: error?.stack,
            code: error?.code
        });
    }

    async info(message, data = null) {
        return this.log('info', message, data);
    }

    async warn(message, data = null) {
        return this.log('warn', message, data);
    }

    async debug(message, data = null) {
        if (this.config.debug) {
            return this.log('debug', message, data);
        }
    }

    async executeCommand(command, options = {}) {
        const defaultOptions = {
            timeout: 30000,
            cwd: process.cwd(),
            env: process.env
        };

        const mergedOptions = { ...defaultOptions, ...options };

        try {
            const { stdout, stderr } = await execPromise(command, mergedOptions);

            await this.debug('Command executed', {
                command,
                stdout: stdout.substring(0, 500), // Limit output
                stderr: stderr.substring(0, 500)
            });

            return {
                success: true,
                stdout: stdout,
                stderr: stderr,
                command: command
            };
        } catch (error) {
            await this.error('Command failed', {
                command,
                error: error.message,
                stdout: error.stdout,
                stderr: error.stderr,
                code: error.code
            });

            return {
                success: false,
                error: error.message,
                stdout: error.stdout,
                stderr: error.stderr,
                code: error.code,
                command: command
            };
        }
    }

    async isProcessRunning(processName) {
        try {
            const { stdout } = await execPromise(`pgrep -f "${processName}"`);
            return stdout.trim().length > 0;
        } catch (error) {
            return false;
        }
    }

    async startProcess(command, options = {}) {
        return this.executeCommand(command, options);
    }

    async stopProcess(processName) {
        try {
            const { stdout } = await execPromise(`pkill -f "${processName}"`);
            return { success: true, output: stdout };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async restartProcess(processName, startCommand) {
        await this.stopProcess(processName);
        await this.sleep(1000);
        return this.startProcess(startCommand);
    }

    async getNetworkInterfaces() {
        const interfaces = os.networkInterfaces();
        const result = {};

        for (const [name, addresses] of Object.entries(interfaces)) {
            result[name] = addresses.map(addr => ({
                address: addr.address,
                netmask: addr.netmask,
                family: addr.family,
                mac: addr.mac,
                internal: addr.internal,
                cidr: addr.cidr
            }));
        }

        return result;
    }

    async scanLocalPorts() {
        try {
            const { stdout } = await execPromise('ss -tuln');
            const ports = [];

            const lines = stdout.split('\n').slice(1);
            for (const line of lines) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 5) {
                    const local = parts[3];
                    const [ip, port] = local.split(':');

                    if (port) {
                        ports.push({
                            protocol: parts[0],
                            state: parts[1],
                            local: local,
                            ip: ip,
                            port: parseInt(port),
                            process: await this.getProcessByPort(parseInt(port))
                        });
                    }
                }
            }

            return ports;
        } catch (error) {
            await this.error('Port scan failed', error);
            return [];
        }
    }

    async getProcessByPort(port) {
        try {
            const { stdout } = await execPromise(`lsof -i :${port} -t`);
            const pid = stdout.trim();

            if (pid) {
                const { stdout: psOutput } = await execPromise(`ps -p ${pid} -o comm=`);
                return {
                    pid: parseInt(pid),
                    name: psOutput.trim()
                };
            }

            return null;
        } catch (error) {
            return null;
        }
    }

    async dnsLookup(hostname, type = 'A') {
        try {
            const { stdout } = await execPromise(`dig ${type} ${hostname} +short`);
            const results = stdout.trim().split('\n').filter(Boolean);

            return {
                hostname,
                type,
                results,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            return {
                hostname,
                type,
                error: error.message,
                timestamp: new Date().toISOString()
            };
        }
    }

    async pingHost(host, count = 4) {
        try {
            const { stdout } = await execPromise(`ping -c ${count} ${host}`);

            const lines = stdout.split('\n');
            const stats = lines.find(line => line.includes('packets transmitted'));

            if (stats) {
                const match = stats.match(/(\d+) packets transmitted, (\d+) received, (\d+)% packet loss/);
                if (match) {
                    return {
                        host,
                        transmitted: parseInt(match[1]),
                        received: parseInt(match[2]),
                        loss: parseFloat(match[3]),
                        reachable: parseInt(match[2]) > 0
                    };
                }
            }

            return { host, error: 'Could not parse ping output' };
        } catch (error) {
            return { host, error: error.message };
        }
    }

    async getSSLCertificate(host, port = 443) {
        try {
            const { stdout } = await execPromise(
                `echo | openssl s_client -connect ${host}:${port} -servername ${host} 2>/dev/null | openssl x509 -noout -text`
            );

            const certInfo = {
                host,
                port,
                valid: false,
                details: {}
            };

            const cnMatch = stdout.match(/Subject:.*CN=([^\n,]+)/);
            if (cnMatch) certInfo.details.commonName = cnMatch[1].trim();

            const issuerMatch = stdout.match(/Issuer: (.+)/);
            if (issuerMatch) certInfo.details.issuer = issuerMatch[1].trim();

            const notBeforeMatch = stdout.match(/Not Before: (.+)/);
            const notAfterMatch = stdout.match(/Not After: (.+)/);

            if (notBeforeMatch && notAfterMatch) {
                certInfo.details.validFrom = new Date(notBeforeMatch[1].trim());
                certInfo.details.validTo = new Date(notAfterMatch[1].trim());
                certInfo.details.daysRemaining = Math.floor(
                    (certInfo.details.validTo - new Date()) / (1000 * 60 * 60 * 24)
                );
                certInfo.valid = certInfo.details.daysRemaining > 0;
            }

            const serialMatch = stdout.match(/Serial Number: (.+)/);
            if (serialMatch) certInfo.details.serial = serialMatch[1].trim();

            const sigMatch = stdout.match(/Signature Algorithm: (.+)/);
            if (sigMatch) certInfo.details.signatureAlgorithm = sigMatch[1].trim();

            return certInfo;
        } catch (error) {
            return { host, port, error: error.message };
        }
    }

    async loadConfig(configPath, defaultConfig = {}) {
        try {
            if (await this.pathExists(configPath)) {
                const content = await this.readFile(configPath);

                if (configPath.endsWith('.json')) {
                    return JSON.parse(content);
                } else if (configPath.endsWith('.yaml') || configPath.endsWith('.yml')) {
                    const yaml = require('yaml');
                    return yaml.parse(content);
                } else if (configPath.endsWith('.js')) {
                    return require(configPath);
                }
            }

            return defaultConfig;
        } catch (error) {
            await this.error('Config load failed', error);
            return defaultConfig;
        }
    }

    async saveConfig(configPath, config, format = 'json') {
        try {
            let content;

            if (format === 'json') {
                content = JSON.stringify(config, null, 2);
            } else if (format === 'yaml') {
                const yaml = require('yaml');
                content = yaml.stringify(config);
            } else {
                throw new Error(`Unsupported format: ${format}`);
            }

            await this.writeFile(configPath, content);
            return true;
        } catch (error) {
            await this.error('Config save failed', error);
            return false;
        }
    }

    async createBackup(source, destination, options = {}) {
        const defaultOptions = {
            compress: true,
            timestamp: true,
            exclude: []
        };

        const opts = { ...defaultOptions, ...options };
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

        let backupName = path.basename(source);
        if (opts.timestamp) {
            backupName += `-${timestamp}`;
        }

        const backupPath = path.join(destination, backupName);

        try {
            await this.ensureDir(destination);

            if (opts.compress) {
                const tarCommand = `tar -czf ${backupPath}.tar.gz -C ${path.dirname(source)} ${path.basename(source)}`;
                await this.executeCommand(tarCommand);
                return `${backupPath}.tar.gz`;
            } else {
                const cpCommand = `cp -r ${source} ${backupPath}`;
                await this.executeCommand(cpCommand);
                return backupPath;
            }
        } catch (error) {
            await this.error('Backup creation failed', error);
            throw error;
        }
    }

    async restoreBackup(backupPath, destination, options = {}) {
        try {
            if (backupPath.endsWith('.tar.gz') || backupPath.endsWith('.tgz')) {
                const tarCommand = `tar -xzf ${backupPath} -C ${destination}`;
                await this.executeCommand(tarCommand);
            } else if (backupPath.endsWith('.zip')) {
                const unzipCommand = `unzip -o ${backupPath} -d ${destination}`;
                await this.executeCommand(unzipCommand);
            } else {
                const cpCommand = `cp -r ${backupPath} ${destination}`;
                await this.executeCommand(cpCommand);
            }

            return true;
        } catch (error) {
            await this.error('Backup restore failed', error);
            throw error;
        }
    }

    async cleanupOldBackups(backupDir, pattern, daysToKeep) {
        try {
            const files = await this.listFiles(backupDir);
            const now = Date.now();
            const cutoff = now - (daysToKeep * 24 * 60 * 60 * 1000);
            const regex = new RegExp(pattern);

            for (const file of files) {
                if (regex.test(file)) {
                    const filePath = path.join(backupDir, file);
                    const stats = await fs.promises.stat(filePath);

                    if (stats.mtimeMs < cutoff) {
                        await this.deleteFile(filePath);
                        await this.info(`Deleted old backup: ${file}`);
                    }
                }
            }

            return true;
        } catch (error) {
            await this.error('Backup cleanup failed', error);
            return false;
        }
    }

    formatSize(bytes) {
        if (bytes === 0) return '0 Bytes';

        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));

        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    formatTime(ms) {
        if (ms < 1000) return `${ms}ms`;
        if (ms < 60000) return `${(ms / 1000).toFixed(2)}s`;
        if (ms < 3600000) return `${(ms / 60000).toFixed(2)}m`;
        return `${(ms / 3600000).toFixed(2)}h`;
    }

    generateUUID() {
        return crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
}

module.exports = Utils;