const { exec } = require('child_process');
const util = require('util');
const fs = require('fs');
const path = require('path');

const execPromise = util.promisify(exec);

class IPTablesManager {
    constructor(config = {}) {
        this.config = {
            sudo: config.sudo !== false,
            ipv6: config.ipv6 || false,
            backupDir: config.backupDir || '/etc/iptables/backups',
            chains: ['INPUT', 'OUTPUT', 'FORWARD'],
            tables: ['filter', 'nat', 'mangle', 'raw', 'security'],
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

    getIPTablesCommand() {
        return this.config.ipv6 ? 'ip6tables' : 'iptables';
    }

    async getStatus() {
        try {
            const commands = [
                `${this.getSudoCommand()} ${this.getIPTablesCommand()} -L -n -v`,
                `${this.getSudoCommand()} ${this.getIPTablesCommand()} -t nat -L -n -v`,
                `${this.getSudoCommand()} ${this.getIPTablesCommand()} -t mangle -L -n -v`
            ];

            const results = await Promise.all(
                commands.map(cmd => execPromise(cmd).catch(() => ({ stdout: '' })))
            );

            const tables = {
                filter: this.parseTableOutput(results[0].stdout),
                nat: this.parseTableOutput(results[1].stdout),
                mangle: this.parseTableOutput(results[2].stdout)
            };

            const policyCmd = `${this.getSudoCommand()} ${this.getIPTablesCommand()} -L -n | grep -E "^Chain (INPUT|OUTPUT|FORWARD)"`;
            const { stdout: policyOutput } = await execPromise(policyCmd).catch(() => ({ stdout: '' }));

            const policies = this.parsePolicies(policyOutput);

            return {
                active: true,
                ipv6: this.config.ipv6,
                tables: tables,
                policies: policies,
                version: await this.getVersion(),
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw new Error(`iptables status check failed: ${error.message}`);
        }
    }

    async getVersion() {
        try {
            const { stdout } = await execPromise(
                `${this.getSudoCommand()} ${this.getIPTablesCommand()} --version`
            );
            return stdout.split(' ')[1];
        } catch (error) {
            return 'Unknown';
        }
    }

    parseTableOutput(output) {
        const lines = output.split('\n');
        const chains = {};
        let currentChain = null;

        for (const line of lines) {
            const chainMatch = line.match(/^Chain (\w+) \(policy (\w+)/);
            if (chainMatch) {
                const [, chain, policy] = chainMatch;
                currentChain = chain;
                chains[currentChain] = {
                    policy: policy,
                    packets: 0,
                    bytes: 0,
                    rules: []
                };
                continue;
            }

            const ruleMatch = line.match(/^\s*(\d+)\s+(\d+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)/);
            if (ruleMatch && currentChain) {
                const [, pkts, bytes, target, prot, opt, source, destination, extra] = ruleMatch;

                const rule = {
                    packets: parseInt(pkts),
                    bytes: parseInt(bytes),
                    target: target,
                    protocol: prot === 'all' ? 'any' : prot,
                    options: opt,
                    source: source,
                    destination: destination,
                    extra: extra
                };

                const portMatch = extra.match(/dpts?:(\d+(?::\d+)?)/);
                if (portMatch) {
                    rule.ports = portMatch[1];
                }

                chains[currentChain].rules.push(rule);
                chains[currentChain].packets += rule.packets;
                chains[currentChain].bytes += rule.bytes;
            }
        }

        return chains;
    }

    parsePolicies(output) {
        const policies = {};
        const lines = output.split('\n');

        for (const line of lines) {
            const match = line.match(/^Chain (\w+) \(policy (\w+)/);
            if (match) {
                const [, chain, policy] = match;
                policies[chain] = policy;
            }
        }

        return policies;
    }

    async addRule(rule) {
        try {
            const {
                chain = 'INPUT',
                table = 'filter',
                target = 'ACCEPT',
                protocol = 'tcp',
                source,
                destination,
                sport,
                dport,
                inInterface,
                outInterface,
                state,
                comment = '',
                jump = null
            } = rule;

            let command = `${this.getSudoCommand()} ${this.getIPTablesCommand()}`;

            if (table !== 'filter') {
                command += ` -t ${table}`;
            }

            command += ` -A ${chain}`;

            if (protocol && protocol !== 'any') {
                command += ` -p ${protocol}`;
            }

            if (source) {
                command += ` -s ${source}`;
            }

            if (destination) {
                command += ` -d ${destination}`;
            }

            if (sport) {
                command += ` --sport ${sport}`;
            }

            if (dport) {
                command += ` --dport ${dport}`;
            }

            if (inInterface) {
                command += ` -i ${inInterface}`;
            }

            if (outInterface) {
                command += ` -o ${outInterface}`;
            }

            if (state) {
                command += ` -m state --state ${state}`;
            }

            if (comment && await this.hasCommentModule()) {
                command += ` -m comment --comment "${comment}"`;
            }
            command += ` -j ${jump || target}`;

            const { stdout, stderr } = await execPromise(command);

            await this.logRuleAction('add', rule, stdout);

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

    async hasCommentModule() {
        try {
            const { stdout } = await execPromise(
                `${this.getSudoCommand()} ${this.getIPTablesCommand()} -m comment --help`
            );
            return stdout.includes('comment match');
        } catch (error) {
            return false;
        }
    }

    async deleteRule(ruleSpec) {
        try {
            let command = `${this.getSudoCommand()} ${this.getIPTablesCommand()}`;

            if (ruleSpec.table && ruleSpec.table !== 'filter') {
                command += ` -t ${ruleSpec.table}`;
            }

            if (ruleSpec.ruleNumber) {
                command += ` -D ${ruleSpec.chain} ${ruleSpec.ruleNumber}`;
            } else {
                command += ` -D ${ruleSpec.chain}`;

                if (ruleSpec.protocol) command += ` -p ${ruleSpec.protocol}`;
                if (ruleSpec.source) command += ` -s ${ruleSpec.source}`;
                if (ruleSpec.destination) command += ` -d ${ruleSpec.destination}`;
                if (ruleSpec.dport) command += ` --dport ${ruleSpec.dport}`;
                if (ruleSpec.inInterface) command += ` -i ${ruleSpec.inInterface}`;
                if (ruleSpec.target) command += ` -j ${ruleSpec.target}`;
            }

            const { stdout, stderr } = await execPromise(command);

            await this.logRuleAction('delete', ruleSpec, stdout);

            return {
                success: true,
                message: 'Rule deleted successfully',
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to delete rule: ${error.message}`);
        }
    }

    async listRules(chain = 'INPUT', table = 'filter') {
        try {
            let command = `${this.getSudoCommand()} ${this.getIPTablesCommand()}`;

            if (table !== 'filter') {
                command += ` -t ${table}`;
            }

            command += ` -L ${chain} -n --line-numbers`;

            const { stdout } = await execPromise(command);
            return this.parseListOutput(stdout);
        } catch (error) {
            throw new Error(`Failed to list rules: ${error.message}`);
        }
    }

    parseListOutput(output) {
        const lines = output.split('\n');
        const rules = [];
        let inChainSection = false;

        for (const line of lines) {
            if (line.startsWith('Chain')) {
                inChainSection = true;
                continue;
            }

            if (inChainSection && line.trim() && !line.startsWith('target')) {
                const rule = this.parseRuleLine(line);
                if (rule) {
                    rules.push(rule);
                }
            }
        }

        return rules;
    }

    parseRuleLine(line) {
        const parts = line.trim().split(/\s+/);

        if (parts.length >= 7) {
            return {
                num: parseInt(parts[0]),
                target: parts[1],
                prot: parts[2],
                opt: parts[3],
                source: parts[4],
                destination: parts[5],
                extra: parts.slice(6).join(' ')
            };
        }

        return null;
    }

    async setPolicy(chain, policy, table = 'filter') {
        try {
            const validPolicies = ['ACCEPT', 'DROP', 'REJECT'];
            if (!validPolicies.includes(policy)) {
                throw new Error(`Invalid policy. Use: ${validPolicies.join(', ')}`);
            }

            const command = `${this.getSudoCommand()} ${this.getIPTablesCommand()} -t ${table} -P ${chain} ${policy}`;
            const { stdout } = await execPromise(command);

            return {
                success: true,
                message: `Policy set: ${chain} -> ${policy}`,
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to set policy: ${error.message}`);
        }
    }

    async openPort(port, protocol = 'tcp', chain = 'INPUT') {
        try {
            const command = `${this.getSudoCommand()} ${this.getIPTablesCommand()} -A ${chain} -p ${protocol} --dport ${port} -j ACCEPT`;
            const { stdout } = await execPromise(command);

            return {
                success: true,
                message: `Port opened: ${port}/${protocol}`,
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to open port: ${error.message}`);
        }
    }

    async closePort(port, protocol = 'tcp', chain = 'INPUT') {
        try {
            const command = `${this.getSudoCommand()} ${this.getIPTablesCommand()} -A ${chain} -p ${protocol} --dport ${port} -j DROP`;
            const { stdout } = await execPromise(command);

            return {
                success: true,
                message: `Port closed: ${port}/${protocol}`,
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to close port: ${error.message}`);
        }
    }

    async blockIP(ip, chain = 'INPUT') {
        try {
            const command = `${this.getSudoCommand()} ${this.getIPTablesCommand()} -A ${chain} -s ${ip} -j DROP`;
            const { stdout } = await execPromise(command);

            return {
                success: true,
                message: `IP blocked: ${ip}`,
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to block IP: ${error.message}`);
        }
    }

    async allowIP(ip, chain = 'INPUT') {
        try {
            const command = `${this.getSudoCommand()} ${this.getIPTablesCommand()} -A ${chain} -s ${ip} -j ACCEPT`;
            const { stdout } = await execPromise(command);

            return {
                success: true,
                message: `IP allowed: ${ip}`,
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to allow IP: ${error.message}`);
        }
    }

    async addRateLimit(port, protocol = 'tcp', limit = '30/minute', burst = 5) {
        try {
            const commands = [
                `${this.getSudoCommand()} ${this.getIPTablesCommand()} -N RATE_LIMIT_${port}`,
                `${this.getSudoCommand()} ${this.getIPTablesCommand()} -A RATE_LIMIT_${port} -m limit --limit ${limit} --limit-burst ${burst} -j RETURN`,
                `${this.getSudoCommand()} ${this.getIPTablesCommand()} -A RATE_LIMIT_${port} -j DROP`,
                `${this.getSudoCommand()} ${this.getIPTablesCommand()} -A INPUT -p ${protocol} --dport ${port} -j RATE_LIMIT_${port}`
            ];

            const results = [];
            for (const cmd of commands) {
                const { stdout } = await execPromise(cmd);
                results.push(stdout);
            }

            return {
                success: true,
                message: `Rate limit added: ${port}/${protocol} (${limit})`,
                output: results.join('\n')
            };
        } catch (error) {
            throw new Error(`Failed to add rate limit: ${error.message}`);
        }
    }

    async addPortForward(sourcePort, destIP, destPort, protocol = 'tcp') {
        try {
            const commands = [
                `${this.getSudoCommand()} ${this.getIPTablesCommand()} -t nat -A PREROUTING -p ${protocol} --dport ${sourcePort} -j DNAT --to-destination ${destIP}:${destPort}`,
                `${this.getSudoCommand()} ${this.getIPTablesCommand()} -A FORWARD -p ${protocol} -d ${destIP} --dport ${destPort} -j ACCEPT`
            ];

            const results = [];
            for (const cmd of commands) {
                const { stdout } = await execPromise(cmd);
                results.push(stdout);
            }

            return {
                success: true,
                message: `Port forward added: ${sourcePort} -> ${destIP}:${destPort}`,
                output: results.join('\n')
            };
        } catch (error) {
            throw new Error(`Failed to add port forward: ${error.message}`);
        }
    }

    async createChain(chainName, table = 'filter') {
        try {
            const command = `${this.getSudoCommand()} ${this.getIPTablesCommand()} -t ${table} -N ${chainName}`;
            const { stdout } = await execPromise(command);

            return {
                success: true,
                message: `Chain created: ${chainName}`,
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to create chain: ${error.message}`);
        }
    }

    async deleteChain(chainName, table = 'filter') {
        try {
            await execPromise(`${this.getSudoCommand()} ${this.getIPTablesCommand()} -t ${table} -F ${chainName}`);

            const command = `${this.getSudoCommand()} ${this.getIPTablesCommand()} -t ${table} -X ${chainName}`;
            const { stdout } = await execPromise(command);

            return {
                success: true,
                message: `Chain deleted: ${chainName}`,
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to delete chain: ${error.message}`);
        }
    }

    async flushRules(table = null) {
        try {
            let command = `${this.getSudoCommand()} ${this.getIPTablesCommand()}`;

            if (table) {
                command += ` -t ${table}`;
            }

            command += ' -F'; // Flush all rules

            const { stdout } = await execPromise(command);

            return {
                success: true,
                message: table ? `Table ${table} flushed` : 'All rules flushed',
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to flush rules: ${error.message}`);
        }
    }

    async flushAll() {
        try {
            const tables = this.config.tables;
            const results = [];

            for (const table of tables) {
                try {
                    const result = await this.flushRules(table);
                    results.push(result);
                } catch (error) {
                }
            }

            return {
                success: true,
                message: 'All tables flushed',
                results: results
            };
        } catch (error) {
            throw new Error(`Failed to flush all: ${error.message}`);
        }
    }

    async backupRules(reason = 'manual') {
        try {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const backupFile = path.join(this.config.backupDir, `iptables-backup-${timestamp}.rules`);

            const command = `${this.getSudoCommand()} ${this.getIPTablesCommand()}-save`;
            const { stdout } = await execPromise(command);

            fs.writeFileSync(backupFile, stdout, 'utf8');

            const metadata = {
                timestamp: new Date().toISOString(),
                reason: reason,
                ipv6: this.config.ipv6,
                file: backupFile
            };

            const metaFile = backupFile.replace('.rules', '.json');
            fs.writeFileSync(metaFile, JSON.stringify(metadata, null, 2), 'utf8');

            return {
                success: true,
                message: 'Backup created successfully',
                file: backupFile,
                metadata: metaFile
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

            const command = `${this.getSudoCommand()} ${this.getIPTablesCommand()}-restore < ${backupFile}`;
            const { stdout, stderr } = await execPromise(command);

            return {
                success: true,
                message: 'Restored from backup successfully',
                file: backupFile,
                output: stdout
            };
        } catch (error) {
            throw new Error(`Restore failed: ${error.message}`);
        }
    }

    async logRuleAction(action, rule, output) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            action: action,
            rule: rule,
            output: output,
            ipv6: this.config.ipv6,
            user: process.env.USER || 'system'
        };

        const logFile = path.join(this.config.backupDir, 'actions.log');
        fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
    }

    async resetCounters() {
        try {
            const command = `${this.getSudoCommand()} ${this.getIPTablesCommand()} -Z`;
            const { stdout } = await execPromise(command);

            return {
                success: true,
                message: 'Counters reset successfully',
                output: stdout
            };
        } catch (error) {
            throw new Error(`Failed to reset counters: ${error.message}`);
        }
    }

    async getConnections() {
        try {
            const command = `${this.getSudoCommand()} conntrack -L`;
            const { stdout } = await execPromise(command).catch(() => ({ stdout: '' }));

            const connections = stdout
                .split('\n')
                .filter(line => line.trim())
                .map(line => {
                    const parts = line.split(/\s+/);
                    return {
                        protocol: parts[0],
                        source: parts[4],
                        destination: parts[6],
                        state: parts[3],
                        timeout: parts[1]
                    };
                });

            return connections;
        } catch (error) {
            throw new Error(`Failed to get connections: ${error.message}`);
        }
    }
}

module.exports = IPTablesManager;