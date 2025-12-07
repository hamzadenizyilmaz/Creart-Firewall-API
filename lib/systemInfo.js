const os = require('os');
const { exec } = require('child_process');
const util = require('util');
const fs = require('fs');
const path = require('path');
const net = require('net');

const execPromise = util.promisify(exec);

class SystemInfo {
    constructor(config = {}) {
        this.config = {
            updateInterval: config.updateInterval || 5000,
            logRetention: config.logRetention || 30,
            monitoring: config.monitoring !== false,
            ...config
        };

        this.metricsHistory = [];
        this.maxHistorySize = 1000;
    }

    async getSystemInfo() {
        try {
            const [
                cpuInfo,
                memoryInfo,
                diskInfo,
                networkInfo,
                uptimeInfo,
                loadInfo,
                processesInfo
            ] = await Promise.all([
                this.getCPUInfo(),
                this.getMemoryInfo(),
                this.getDiskInfo(),
                this.getNetworkInfo(),
                this.getUptime(),
                this.getLoadAverage(),
                this.getProcesses()
            ]);

            return {
                hostname: os.hostname(),
                platform: os.platform(),
                arch: os.arch(),
                release: os.release(),
                type: os.type(),
                cpu: cpuInfo,
                memory: memoryInfo,
                disk: diskInfo,
                network: networkInfo,
                uptime: uptimeInfo,
                load: loadInfo,
                processes: processesInfo,
                users: os.userInfo(),
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw new Error(`Failed to get system info: ${error.message}`);
        }
    }

    async getCPUInfo() {
        try {
            const cpus = os.cpus();
            const loadavg = os.loadavg();

            let totalIdle = 0, totalTick = 0;

            cpus.forEach(cpu => {
                for (const type in cpu.times) {
                    totalTick += cpu.times[type];
                }
                totalIdle += cpu.times.idle;
            });

            const totalUsage = ((totalTick - totalIdle) / totalTick) * 100;

            return {
                model: cpus[0].model,
                cores: cpus.length,
                speed: cpus[0].speed,
                usage: totalUsage.toFixed(2),
                load1: loadavg[0],
                load5: loadavg[1],
                load15: loadavg[2],
                details: cpus.map(cpu => ({
                    model: cpu.model,
                    speed: cpu.speed,
                    times: cpu.times
                }))
            };
        } catch (error) {
            return {
                model: 'Unknown',
                cores: 0,
                speed: 0,
                usage: 0,
                error: error.message
            };
        }
    }


    async getMemoryInfo() {
        try {
            const total = os.totalmem();
            const free = os.freemem();
            const used = total - free;
            const usage = (used / total) * 100;

            const { stdout } = await execPromise('free -b').catch(() => ({ stdout: '' }));
            let swapTotal = 0, swapUsed = 0, swapFree = 0;

            if (stdout) {
                const lines = stdout.split('\n');
                if (lines.length > 2) {
                    const swapLine = lines[2].split(/\s+/).filter(Boolean);
                    if (swapLine.length >= 3) {
                        swapTotal = parseInt(swapLine[1]);
                        swapUsed = parseInt(swapLine[2]);
                        swapFree = swapTotal - swapUsed;
                    }
                }
            }

            return {
                total: this.formatBytes(total),
                free: this.formatBytes(free),
                used: this.formatBytes(used),
                usage: usage.toFixed(2),
                swap: {
                    total: this.formatBytes(swapTotal),
                    used: this.formatBytes(swapUsed),
                    free: this.formatBytes(swapFree),
                    usage: swapTotal > 0 ? ((swapUsed / swapTotal) * 100).toFixed(2) : 0
                },
                raw: {
                    total,
                    free,
                    used,
                    swapTotal,
                    swapUsed,
                    swapFree
                }
            };
        } catch (error) {
            return {
                total: '0',
                free: '0',
                used: '0',
                usage: 0,
                error: error.message
            };
        }
    }

    async getDiskInfo() {
        try {
            const { stdout } = await execPromise('df -B1 --output=source,fstype,size,used,avail,pcent,target');
            const lines = stdout.split('\n').slice(1).filter(Boolean);

            const disks = lines.map(line => {
                const parts = line.split(/\s+/).filter(Boolean);
                if (parts.length >= 7) {
                    const total = parseInt(parts[2]);
                    const used = parseInt(parts[3]);
                    const available = parseInt(parts[4]);
                    const usage = parseInt(parts[5]);

                    return {
                        filesystem: parts[0],
                        type: parts[1],
                        total: this.formatBytes(total),
                        used: this.formatBytes(used),
                        available: this.formatBytes(available),
                        usage: usage,
                        mount: parts[6],
                        raw: { total, used, available }
                    };
                }
                return null;
            }).filter(disk => disk !== null);

            const ioStats = await this.getIOStats();

            return {
                disks: disks,
                io: ioStats,
                total: this.calculateDiskTotals(disks)
            };
        } catch (error) {
            return {
                disks: [],
                error: error.message
            };
        }
    }

    async getIOStats() {
        try {
            const { stdout } = await execPromise('iostat -d -x 1 2');
            const lines = stdout.split('\n');

            const statsLines = lines.slice(lines.length - 10).filter(line =>
                line.trim() && !line.includes('Device') && !line.includes('Linux')
            );

            const devices = statsLines.map(line => {
                const parts = line.split(/\s+/).filter(Boolean);
                if (parts.length >= 7) {
                    return {
                        device: parts[0],
                        rrqm: parseFloat(parts[1]),
                        wrqm: parseFloat(parts[2]),
                        r: parseFloat(parts[3]),
                        w: parseFloat(parts[4]),
                        rkB: parseFloat(parts[5]),
                        wkB: parseFloat(parts[6]),
                        await: parseFloat(parts[7]),
                        util: parseFloat(parts[8])
                    };
                }
                return null;
            }).filter(device => device !== null);

            return devices;
        } catch (error) {
            return [];
        }
    }

    calculateDiskTotals(disks) {
        const totals = disks.reduce((acc, disk) => {
            acc.total += disk.raw.total;
            acc.used += disk.raw.used;
            acc.available += disk.raw.available;
            return acc;
        }, { total: 0, used: 0, available: 0 });

        return {
            total: this.formatBytes(totals.total),
            used: this.formatBytes(totals.used),
            available: this.formatBytes(totals.available),
            usage: ((totals.used / totals.total) * 100).toFixed(2)
        };
    }

    async getNetworkInfo() {
        try {
            const interfaces = os.networkInterfaces();
            const networkStats = [];

            for (const [name, addresses] of Object.entries(interfaces)) {
                for (const address of addresses) {
                    if (address.family === 'IPv4' && !address.internal) {
                        networkStats.push({
                            interface: name,
                            address: address.address,
                            netmask: address.netmask,
                            mac: await this.getMACAddress(name),
                            speed: await this.getInterfaceSpeed(name),
                            status: await this.getInterfaceStatus(name)
                        });
                    }
                }
            }

            const traffic = await this.getNetworkTraffic();

            const openPorts = await this.getOpenPorts();

            const dnsInfo = await this.getDNSInfo();

            return {
                interfaces: networkStats,
                traffic: traffic,
                openPorts: openPorts,
                dns: dnsInfo,
                gateway: await this.getGateway(),
                publicIP: await this.getPublicIP()
            };
        } catch (error) {
            return {
                interfaces: [],
                error: error.message
            };
        }
    }

    async getMACAddress(interface) {
        try {
            const { stdout } = await execPromise(`cat /sys/class/net/${interface}/address`);
            return stdout.trim();
        } catch (error) {
            return 'Unknown';
        }
    }

    async getInterfaceSpeed(interface) {
        try {
            const { stdout } = await execPromise(`cat /sys/class/net/${interface}/speed 2>/dev/null || echo 0`);
            const speed = parseInt(stdout.trim());
            return speed > 0 ? `${speed} Mbps` : 'Unknown';
        } catch (error) {
            return 'Unknown';
        }
    }

    async getInterfaceStatus(interface) {
        try {
            const { stdout } = await execPromise(`cat /sys/class/net/${interface}/operstate`);
            return stdout.trim();
        } catch (error) {
            return 'unknown';
        }
    }

    async getNetworkTraffic() {
        try {
            const { stdout } = await execPromise('cat /proc/net/dev');
            const lines = stdout.split('\n').slice(2);

            const traffic = {};

            for (const line of lines) {
                const parts = line.split(/\s+/).filter(Boolean);
                if (parts.length >= 10) {
                    const iface = parts[0].replace(':', '');
                    traffic[iface] = {
                        rxBytes: parseInt(parts[1]),
                        rxPackets: parseInt(parts[2]),
                        rxErrors: parseInt(parts[3]),
                        txBytes: parseInt(parts[9]),
                        txPackets: parseInt(parts[10]),
                        txErrors: parseInt(parts[11])
                    };
                }
            }

            return traffic;
        } catch (error) {
            return {};
        }
    }

    async getOpenPorts() {
        try {
            const { stdout } = await execPromise('ss -tuln');
            const lines = stdout.split('\n').slice(1);

            const ports = lines.map(line => {
                const parts = line.split(/\s+/).filter(Boolean);
                if (parts.length >= 5) {
                    const [netid, state, local, peer] = parts;
                    const [address, port] = local.split(':');

                    return {
                        protocol: netid,
                        state: state,
                        address: address,
                        port: parseInt(port),
                        process: this.getProcessByPort(parseInt(port))
                    };
                }
                return null;
            }).filter(port => port !== null);

            return ports;
        } catch (error) {
            return [];
        }
    }

    async getProcessByPort(port) {
        try {
            const { stdout } = await execPromise(`lsof -i :${port} | grep LISTEN`);
            const parts = stdout.split(/\s+/).filter(Boolean);
            return parts.length >= 2 ? parts[0] : 'unknown';
        } catch (error) {
            return 'unknown';
        }
    }

    async getDNSInfo() {
        try {
            const { stdout } = await execPromise('cat /etc/resolv.conf');
            const dnsServers = stdout
                .split('\n')
                .filter(line => line.startsWith('nameserver'))
                .map(line => line.split(/\s+/)[1]);

            return {
                servers: dnsServers,
                domain: await this.getDomain(),
                search: await this.getSearchDomains()
            };
        } catch (error) {
            return { servers: [], error: error.message };
        }
    }

    async getDomain() {
        try {
            const { stdout } = await execPromise('hostname -d');
            return stdout.trim();
        } catch (error) {
            return '';
        }
    }

    async getSearchDomains() {
        try {
            const { stdout } = await execPromise('grep "^search" /etc/resolv.conf');
            return stdout.replace('search', '').trim().split(/\s+/);
        } catch (error) {
            return [];
        }
    }

    async getGateway() {
        try {
            const { stdout } = await execPromise('ip route | grep default');
            const match = stdout.match(/default via (\S+)/);
            return match ? match[1] : 'Unknown';
        } catch (error) {
            return 'Unknown';
        }
    }

    async getPublicIP() {
        try {
            const { stdout } = await execPromise('curl -s ifconfig.me');
            return stdout.trim();
        } catch (error) {
            try {
                const { stdout } = await execPromise('dig +short myip.opendns.com @resolver1.opendns.com');
                return stdout.trim();
            } catch (error2) {
                return 'Unknown';
            }
        }
    }

    async getUptime() {
        try {
            const uptime = os.uptime();
            const { stdout } = await execPromise('uptime -p');

            return {
                seconds: uptime,
                formatted: stdout.trim(),
                bootTime: await this.getBootTime()
            };
        } catch (error) {
            return {
                seconds: os.uptime(),
                formatted: 'Unknown',
                bootTime: 'Unknown'
            };
        }
    }

    async getBootTime() {
        try {
            const { stdout } = await execPromise('who -b');
            const match = stdout.match(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}/);
            return match ? match[0] : 'Unknown';
        } catch (error) {
            return 'Unknown';
        }
    }

    async getLoadAverage() {
        const load = os.loadavg();
        return {
            '1min': load[0],
            '5min': load[1],
            '15min': load[2],
            perCore: load.map(l => (l / os.cpus().length).toFixed(2))
        };
    }

    async getProcesses() {
        try {
            const { stdout } = await execPromise('ps aux --sort=-%cpu | head -20');
            const lines = stdout.split('\n').slice(1);

            const processes = lines.map(line => {
                const parts = line.split(/\s+/).filter(Boolean);
                if (parts.length >= 11) {
                    return {
                        user: parts[0],
                        pid: parseInt(parts[1]),
                        cpu: parseFloat(parts[2]),
                        mem: parseFloat(parts[3]),
                        vsz: parseInt(parts[4]),
                        rss: parseInt(parts[5]),
                        tty: parts[6],
                        stat: parts[7],
                        start: parts[8],
                        time: parts[9],
                        command: parts.slice(10).join(' ')
                    };
                }
                return null;
            }).filter(p => p !== null);

            return {
                total: await this.getTotalProcesses(),
                running: processes.length,
                list: processes
            };
        } catch (error) {
            return {
                total: 0,
                running: 0,
                list: [],
                error: error.message
            };
        }
    }
    async getTotalProcesses() {
        try {
            const { stdout } = await execPromise('ps aux | wc -l');
            return parseInt(stdout.trim()) - 1;
        } catch (error) {
            return 0;
        }
    }

    async getStatus() {
        try {
            const info = await this.getSystemInfo();

            const alarms = await this.checkAlarms(info);

            return {
                ...info,
                alarms: alarms,
                health: this.calculateHealthScore(info, alarms),
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw new Error(`Failed to get status: ${error.message}`);
        }
    }

    async checkAlarms(systemInfo) {
        const alarms = [];

        if (systemInfo.cpu.usage > 90) {
            alarms.push({
                type: 'cpu',
                severity: 'high',
                message: `CPU usage is high: ${systemInfo.cpu.usage}%`,
                threshold: 90,
                current: systemInfo.cpu.usage
            });
        } else if (systemInfo.cpu.usage > 80) {
            alarms.push({
                type: 'cpu',
                severity: 'medium',
                message: `CPU usage is elevated: ${systemInfo.cpu.usage}%`,
                threshold: 80,
                current: systemInfo.cpu.usage
            });
        }

        if (systemInfo.memory.usage > 90) {
            alarms.push({
                type: 'memory',
                severity: 'high',
                message: `Memory usage is high: ${systemInfo.memory.usage}%`,
                threshold: 90,
                current: systemInfo.memory.usage
            });
        }

        if (systemInfo.disk.total && systemInfo.disk.total.usage > 90) {
            alarms.push({
                type: 'disk',
                severity: 'high',
                message: `Disk usage is high: ${systemInfo.disk.total.usage}%`,
                threshold: 90,
                current: systemInfo.disk.total.usage
            });
        }

        const loadPerCore = systemInfo.load['1min'] / systemInfo.cpu.cores;
        if (loadPerCore > 2) {
            alarms.push({
                type: 'load',
                severity: 'high',
                message: `Load average is high: ${systemInfo.load['1min']} (${loadPerCore.toFixed(2)} per core)`,
                threshold: 2,
                current: loadPerCore
            });
        }

        return alarms;
    }

    calculateHealthScore(systemInfo, alarms) {
        let score = 100;

        if (systemInfo.cpu.usage > 90) score -= 30;
        else if (systemInfo.cpu.usage > 80) score -= 15;
        else if (systemInfo.cpu.usage > 70) score -= 5;

        if (systemInfo.memory.usage > 90) score -= 30;
        else if (systemInfo.memory.usage > 80) score -= 15;
        else if (systemInfo.memory.usage > 70) score -= 5;

        if (systemInfo.disk.total && systemInfo.disk.total.usage > 90) score -= 30;
        else if (systemInfo.disk.total && systemInfo.disk.total.usage > 80) score -= 15;

        const loadPerCore = systemInfo.load['1min'] / systemInfo.cpu.cores;
        if (loadPerCore > 2) score -= 20;
        else if (loadPerCore > 1.5) score -= 10;

        const highAlarms = alarms.filter(a => a.severity === 'high').length;
        const mediumAlarms = alarms.filter(a => a.severity === 'medium').length;

        score -= (highAlarms * 10);
        score -= (mediumAlarms * 5);

        return Math.max(0, Math.min(100, Math.round(score)));
    }

    async scanPorts(target, ports = '1-1000', timeout = 1000) {
        try {
            const portRange = this.parsePortRange(ports);
            const openPorts = [];

            for (const port of portRange) {
                const isOpen = await this.checkPort(target, port, timeout);
                if (isOpen) {
                    openPorts.push({
                        port: port,
                        service: await this.getServiceByPort(port),
                        banner: await this.getBanner(target, port, timeout)
                    });
                }
            }

            return {
                target: target,
                totalScanned: portRange.length,
                openPorts: openPorts,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw new Error(`Port scan failed: ${error.message}`);
        }
    }

    parsePortRange(ports) {
        if (ports.includes('-')) {
            const [start, end] = ports.split('-').map(Number);
            return Array.from({ length: end - start + 1 }, (_, i) => start + i);
        } else if (ports.includes(',')) {
            return ports.split(',').map(Number);
        } else {
            return [parseInt(ports)];
        }
    }

    async checkPort(host, port, timeout) {
        return new Promise((resolve) => {
            const socket = new net.Socket();

            socket.setTimeout(timeout);

            socket.on('connect', () => {
                socket.destroy();
                resolve(true);
            });

            socket.on('timeout', () => {
                socket.destroy();
                resolve(false);
            });

            socket.on('error', () => {
                resolve(false);
            });

            socket.connect(port, host);
        });
    }

    async getServiceByPort(port) {
        try {
            const { stdout } = await execPromise(`grep "^${port}/" /etc/services | head -1`);
            const parts = stdout.split(/\s+/);
            return parts.length >= 2 ? parts[1] : 'unknown';
        } catch (error) {
            return 'unknown';
        }
    }

    async getBanner(host, port, timeout) {
        return new Promise((resolve) => {
            const socket = new net.Socket();
            let banner = '';

            socket.setTimeout(timeout);

            socket.on('data', (data) => {
                banner += data.toString();
                if (banner.length > 1024) {
                    socket.destroy();
                    resolve(banner.substring(0, 1024));
                }
            });

            socket.on('timeout', () => {
                socket.destroy();
                resolve(banner || 'No banner');
            });

            socket.on('error', () => {
                resolve('No banner');
            });

            socket.connect(port, host);

            if (port === 80 || port === 443 || port === 8080) {
                socket.write('HEAD / HTTP/1.0\r\n\r\n');
            }
        });
    }

    async ping(host, count = 4) {
        try {
            const { stdout } = await execPromise(`ping -c ${count} ${host}`);

            const lines = stdout.split('\n');
            const statsLine = lines.find(line => line.includes('packets transmitted'));

            if (statsLine) {
                const match = statsLine.match(/(\d+) packets transmitted, (\d+) received, (\d+)% packet loss/);
                if (match) {
                    const [, transmitted, received, loss] = match;

                    const rttLine = lines.find(line => line.includes('rtt min/avg/max/mdev'));
                    let rtt = { min: 0, avg: 0, max: 0 };

                    if (rttLine) {
                        const rttMatch = rttLine.match(/= (\d+\.\d+)\/(\d+\.\d+)\/(\d+\.\d+)\//);
                        if (rttMatch) {
                            rtt = {
                                min: parseFloat(rttMatch[1]),
                                avg: parseFloat(rttMatch[2]),
                                max: parseFloat(rttMatch[3])
                            };
                        }
                    }

                    return {
                        host: host,
                        transmitted: parseInt(transmitted),
                        received: parseInt(received),
                        loss: parseFloat(loss),
                        rtt: rtt,
                        reachable: parseInt(received) > 0
                    };
                }
            }

            return { host: host, error: 'Could not parse ping output' };
        } catch (error) {
            return { host: host, error: error.message };
        }
    }

    async traceRoute(host) {
        try {
            const { stdout } = await execPromise(`traceroute -n ${host} | head -30`);

            const hops = stdout
                .split('\n')
                .slice(1)
                .map(line => {
                    const parts = line.split(/\s+/).filter(Boolean);
                    if (parts.length >= 2 && !isNaN(parts[0])) {
                        return {
                            hop: parseInt(parts[0]),
                            ip: parts[1],
                            times: parts.slice(2).map(t => t.replace('ms', '')).filter(t => t !== '*')
                        };
                    }
                    return null;
                })
                .filter(hop => hop !== null);

            return {
                host: host,
                hops: hops,
                totalHops: hops.length
            };
        } catch (error) {
            return { host: host, error: error.message };
        }
    }

    startMonitoring(callback) {
        if (!this.config.monitoring) {
            return () => { };
        }

        const interval = setInterval(async () => {
            try {
                const status = await this.getStatus();

                this.metricsHistory.push(status);
                if (this.metricsHistory.length > this.maxHistorySize) {
                    this.metricsHistory.shift();
                }

                if (callback) {
                    callback(status);
                }
            } catch (error) {
                console.error('Monitoring error:', error);
            }
        }, this.config.updateInterval);

        return () => clearInterval(interval);
    }

    getMetricsHistory(limit = 100) {
        return this.metricsHistory.slice(-limit);
    }

    async backupSystemInfo() {
        try {
            const info = await this.getSystemInfo();
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const backupFile = `/var/backups/system-info-${timestamp}.json`;

            fs.writeFileSync(backupFile, JSON.stringify(info, null, 2), 'utf8');

            await this.cleanupOldBackups('/var/backups', 'system-info-', this.config.logRetention);

            return {
                success: true,
                file: backupFile,
                timestamp: timestamp
            };
        } catch (error) {
            throw new Error(`Backup failed: ${error.message}`);
        }
    }

    async cleanupOldBackups(directory, prefix, daysToKeep) {
        try {
            const files = fs.readdirSync(directory)
                .filter(file => file.startsWith(prefix) && file.endsWith('.json'))
                .map(file => ({
                    name: file,
                    path: path.join(directory, file),
                    time: fs.statSync(path.join(directory, file)).mtime.getTime()
                }))
                .sort((a, b) => b.time - a.time);

            const cutoff = Date.now() - (daysToKeep * 24 * 60 * 60 * 1000);

            for (const file of files) {
                if (file.time < cutoff) {
                    fs.unlinkSync(file.path);
                }
            }

            return files.length;
        } catch (error) {
            console.error('Cleanup error:', error);
            return 0;
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';

        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));

        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}

module.exports = SystemInfo;