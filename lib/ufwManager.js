const { exec } = require('child_process');
const util = require('util');
const fs = require('fs');
const path = require('path');

const execPromise = util.promisify(exec);

class UFWManager {
    constructor(config = {}) {
        this.config = {
            sudo: config.sudo !== false,
            backupDir: config.backupDir || '/etc/ufw/backups',
            logFile: config.logFile || '/var/log/ufw.log',
            ...config
        };

        this.ensureBackupDir();
    }

    ensureBackupDir() {
        if (!fs.existsSync(this.config.backupDir)) {
            fs.mkdirSync(this.config.backupDir, { recursive: true });
        }
    }

    getSudoCommand() {
        return this.config.sudo ? 'sudo' : '';
    }

    async getStatus() {
        try {
            const { stdout, stderr } = await execPromise(
                `${this.getSudoCommand()} ufw status verbose`
            );

            const isActive = stdout.includes('Status: active');
            const isInactive = stdout.includes('Status: inactive');

            const rules = this.parseUFWStatus(stdout);

            const defaultPolicyMatch = stdout.match(/Default:\s+(\w+)\s+\((\w+)\),\s+(\w+)\s+\((\w+)\)/);
            const defaultPolicies = defaultPolicyMatch ? {
                incoming: defaultPolicyMatch[1],
                incomingDetail: defaultPolicyMatch[2],
                outgoing: defaultPolicyMatch[3],
                outgoingDetail: defaultPolicyMatch[4]
            } : {};

            return {
                active: isActive,
                status: isActive ? 'active' : isInactive ? 'inactive' : 'unknown',
                version: await this.getVersion(),
                rules: rules,
                defaultPolicies: defaultPolicies,
                rawOutput: stdout,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw new Error(`UFW status check failed: ${error.message}`);
        }
    }

    async getVersion() {
        try {
            const { stdout } = await execPromise(
                `${this.getSudoCommand()} ufw version`
            );
            return stdout.trim();
        } catch (error) {
            return 'Unknown';
        }
    }

    parseUFWStatus(output) {
        const lines = output.split('\n');
        const rules = [];
        let inRulesSection = false;

        for (const line of lines) {
            if (line.startsWith('----') || line.includes('To')) {
                inRulesSection = true;
                continue;
            }

            if (inRulesSection && line.trim()) {
                const rule = this.parseRuleLine(line);
                if (rule) {
                    rules.push(rule);
                }
            }
        }

        return rules;
    }

    parseRuleLine(line) {
        const match = line.match(/([\w\/\-\*]+)\s+(\w+)\s+(\w+)\s+(.+)/);

        if (match) {
            const [, port, action, direction, source] = match;

            return {
                port: port.trim(),
                protocol: this.getProtocolFromPort(port),
                action: action.trim().toLowerCase(),
                direction: direction.trim().toLowerCase(),
                source: source.trim(),
                raw: line.trim()
            };
        }

        return null;
    }

    getProtocolFromPort(port) {
        if (port.includes('/')) {
            return port.split('/')[1];
        }
        return 'tcp';
    }

    async enable() {
        try {
            const { stdout, stderr } = await execPromise(
                `${this.getSudoCommand()} ufw --force enable`
            );

            await this.backupRules('enable');

            return {
                success: true,
                message: 'UFW enabled successfully',
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to enable UFW: ${error.message}`);
        }
    }

    async disable() {
        try {
            const { stdout, stderr } = await execPromise(
                `${this.getSudoCommand()} ufw disable`
            );

            await this.backupRules('disable');

            return {
                success: true,
                message: 'UFW disabled successfully',
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to disable UFW: ${error.message}`);
        }
    }

    async setDefaultPolicies(incoming = 'deny', outgoing = 'allow') {
        try {
            const validActions = ['allow', 'deny', 'reject'];

            if (!validActions.includes(incoming) || !validActions.includes(outgoing)) {
                throw new Error('Invalid policy action. Use: allow, deny, reject');
            }

            const commands = [
                `${this.getSudoCommand()} ufw default ${incoming} incoming`,
                `${this.getSudoCommand()} ufw default ${outgoing} outgoing`
            ];

            const results = [];
            for (const cmd of commands) {
                const { stdout } = await execPromise(cmd);
                results.push(stdout);
            }

            return {
                success: true,
                message: `Default policies set: incoming=${incoming}, outgoing=${outgoing}`,
                output: results.join('\n')
            };
        } catch (error) {
            throw new Error(`Failed to set default policies: ${error.message}`);
        }
    }

    async addRule(rule) {
        try {
            const {
                action = 'allow',
                port,
                protocol = 'tcp',
                source,
                direction = 'in',
                comment = '',
                interface = null
            } = rule;

            this.validateRule(rule);

            let command = `${this.getSudoCommand()} ufw ${action}`;

            if (port) {
                command += ` ${port}`;
                if (protocol && protocol !== 'any') {
                    command += `/${protocol}`;
                }
            }

            if (direction === 'out') {
                command += ' out';
            }

            if (source) {
                command += ` from ${source}`;
            }

            if (interface) {
                command += ` on ${interface}`;
            }

            if (comment) {
                command += ` comment '${comment}'`;
            }

            const { stdout, stderr } = await execPromise(command);

            await this.logRuleAction('add', rule, stdout);

            await this.backupRules('add_rule');

            return {
                success: true,
                message: 'Rule added successfully',
                rule: rule,
                command: command,
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to add rule: ${error.message}`);
        }
    }

    validateRule(rule) {
        const { action, port, protocol, direction } = rule;

        const validActions = ['allow', 'deny', 'reject', 'limit'];
        if (!validActions.includes(action)) {
            throw new Error(`Invalid action: ${action}. Valid actions: ${validActions.join(', ')}`);
        }

        if (port) {
            const portRegex = /^(\d+|\d+:\d+)$/;
            if (!portRegex.test(port)) {
                throw new Error(`Invalid port format: ${port}. Use: 80 or 3000:4000`);
            }
        }

        const validProtocols = ['tcp', 'udp', 'any'];
        if (protocol && !validProtocols.includes(protocol)) {
            throw new Error(`Invalid protocol: ${protocol}. Valid protocols: ${validProtocols.join(', ')}`);
        }

        const validDirections = ['in', 'out'];
        if (direction && !validDirections.includes(direction)) {
            throw new Error(`Invalid direction: ${direction}. Valid directions: ${validDirections.join(', ')}`);
        }

        return true;
    }

    async deleteRule(ruleNumber) {
        try {
            const { stdout, stderr } = await execPromise(
                `${this.getSudoCommand()} ufw delete ${ruleNumber}`
            );

            await this.logRuleAction('delete', { ruleNumber }, stdout);

            await this.backupRules('delete_rule');

            return {
                success: true,
                message: `Rule ${ruleNumber} deleted successfully`,
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to delete rule: ${error.message}`);
        }
    }

    async deleteRuleByIP(ip) {
        try {
            const { stdout, stderr } = await execPromise(
                `${this.getSudoCommand()} ufw delete allow from ${ip}`
            );

            return {
                success: true,
                message: `Rules for IP ${ip} deleted successfully`,
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to delete rule by IP: ${error.message}`);
        }
    }

    async getRules() {
        try {
            const { stdout, stderr } = await execPromise(
                `${this.getSudoCommand()} ufw status numbered`
            );

            const rules = [];
            const lines = stdout.split('\n');

            for (const line of lines) {
                const match = line.match(/\[\s*(\d+)\]\s+(.+)/);
                if (match) {
                    const [, number, rulePart] = match;
                    const rule = this.parseRuleLine(rulePart);

                    if (rule) {
                        rules.push({
                            number: parseInt(number),
                            ...rule
                        });
                    }
                }
            }

            return rules;
        } catch (error) {
            throw new Error(`Failed to get rules: ${error.message}`);
        }
    }

    async getRule(number) {
        const rules = await this.getRules();
        return rules.find(rule => rule.number === number);
    }

    async getRulesByPort(port) {
        const rules = await this.getRules();
        return rules.filter(rule => rule.port && rule.port.includes(port.toString()));
    }

    async getRulesByIP(ip) {
        const rules = await this.getRules();
        return rules.filter(rule =>
            rule.source && (rule.source.includes(ip) || rule.source === 'Anywhere')
        );
    }

    async getLogs(limit = 100) {
        try {
            if (!fs.existsSync(this.config.logFile)) {
                return [];
            }

            const logContent = fs.readFileSync(this.config.logFile, 'utf8');
            const lines = logContent.split('\n').reverse().slice(0, limit);

            const logs = lines
                .filter(line => line.trim())
                .map(line => this.parseLogLine(line))
                .filter(log => log !== null);

            return logs;
        } catch (error) {
            throw new Error(`Failed to get logs: ${error.message}`);
        }
    }

    parseLogLine(line) {
        try {
            const parts = line.split(' ');
            const log = {};

            parts.forEach(part => {
                const [key, value] = part.split('=');
                if (key && value) {
                    log[key.toLowerCase()] = value;
                }
            });

            log.timestamp = new Date().toISOString();
            log.raw = line;

            return log;
        } catch (error) {
            return null;
        }
    }

    async logRuleAction(action, rule, output) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            action: action,
            rule: rule,
            output: output,
            user: process.env.USER || 'system'
        };

        const logFile = path.join(this.config.backupDir, 'actions.log');
        fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
    }

    async backupRules(reason = 'manual') {
        try {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const backupFile = path.join(this.config.backupDir, `ufw-backup-${timestamp}.json`);

            const status = await this.getStatus();
            const rules = await this.getRules();

            const backupData = {
                timestamp: new Date().toISOString(),
                reason: reason,
                status: status,
                rules: rules,
                config: this.config
            };

            fs.writeFileSync(backupFile, JSON.stringify(backupData, null, 2), 'utf8');

            return {
                success: true,
                message: 'Backup created successfully',
                file: backupFile
            };
        } catch (error) {
            throw new Error(`Backup failed: ${error.message}`);
        }
    }

    async restoreFromBackup(backupFile) {
        try {
            if (!fs.existsSync(backupFile)) {
                throw new Error(`Backup file not found: ${backupFile}`);
            }

            const backupData = JSON.parse(fs.readFileSync(backupFile, 'utf8'));

            await this.resetRules();

            for (const rule of backupData.rules) {
                await this.addRule(rule);
            }

            if (backupData.status.defaultPolicies) {
                const { incoming, outgoing } = backupData.status.defaultPolicies;
                await this.setDefaultPolicies(incoming, outgoing);
            }

            return {
                success: true,
                message: 'Restored from backup successfully',
                rulesRestored: backupData.rules.length
            };
        } catch (error) {
            throw new Error(`Restore failed: ${error.message}`);
        }
    }

    async resetRules() {
        try {
            await this.disable();

            const { stdout } = await execPromise(
                `${this.getSudoCommand()} ufw --force reset`
            );

            await this.enable();

            return {
                success: true,
                message: 'UFW rules reset successfully',
                output: stdout
            };
        } catch (error) {
            throw new Error(`Reset failed: ${error.message}`);
        }
    }

    async addRateLimitRule(port, protocol = 'tcp', limit = '30/minute') {
        try {
            const { stdout } = await execPromise(
                `${this.getSudoCommand()} ufw limit ${port}/${protocol} comment 'Rate limit: ${limit}'`
            );

            return {
                success: true,
                message: `Rate limit rule added: ${port}/${protocol} (${limit})`,
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to add rate limit: ${error.message}`);
        }
    }

    async listApplications() {
        try {
            const { stdout } = await execPromise(
                `${this.getSudoCommand()} ufw app list`
            );

            const apps = stdout
                .split('\n')
                .filter(line => line.includes('-'))
                .map(line => line.trim().replace('Available applications:', '').trim())
                .filter(app => app);

            return apps;
        } catch (error) {
            throw new Error(`Failed to list applications: ${error.message}`);
        }
    }

    async addRuleByApp(appName, action = 'allow') {
        try {
            const { stdout } = await execPromise(
                `${this.getSudoCommand()} ufw ${action} '${appName}'`
            );

            return {
                success: true,
                message: `Application rule added: ${appName} (${action})`,
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to add application rule: ${error.message}`);
        }
    }

    watchLogs(callback, interval = 1000) {
        let lastSize = 0;

        const watchInterval = setInterval(async () => {
            try {
                if (!fs.existsSync(this.config.logFile)) {
                    return;
                }

                const stats = fs.statSync(this.config.logFile);
                if (stats.size > lastSize) {
                    const newLogs = await this.getLogs(10);
                    if (newLogs.length > 0) {
                        callback(newLogs);
                    }
                    lastSize = stats.size;
                }
            } catch (error) {
                console.error('Log watch error:', error);
            }
        }, interval);

        return () => clearInterval(watchInterval);
    }
}

module.exports = UFWManager;