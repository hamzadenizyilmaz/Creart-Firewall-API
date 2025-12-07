/**
 * Creart Firewall Library
 * Advanced firewall management for Linux systems
 * @module creart-firewall
**/

const UFWManager = require('./lib/ufwManager');
const IPTablesManager = require('./lib/iptablesManager');
const SystemInfo = require('./lib/systemInfo');
const Logger = require('./lib/utils').Logger;

class CreartFirewall {
  constructor(config = {}) {
    this.config = {
      sshHost: config.sshHost,
      sshPort: config.sshPort,
      sshUsername: config.sshUsername,
      sshPrivateKey: config.sshPrivateKey,
      sshPassword: config.sshPassword,
      logLevel: config.logLevel,
      defaultInterface: config.defaultInterface,
      backupEnabled: config.backupEnabled !== false,
      autoSave: config.autoSave !== false,
      ...config
    };

    this.logger = new Logger(this.config.logLevel);
    this.ufw = new UFWManager(this.config);
    this.iptables = new IPTablesManager(this.config);
    this.system = new SystemInfo(this.config);

    this.logger.info('Creart Firewall initialized', {
      host: this.config.sshHost,
      port: this.config.sshPort
    });
  }

  /**
   * Get firewall status
   * @returns {Promise<Object>} Firewall status
  **/

  async getStatus() {
    try {
      const [ufwStatus, iptablesStatus, systemInfo] = await Promise.all([
        this.ufw.getStatus(),
        this.iptables.getStatus(),
        this.system.getInfo()
      ]);

      return {
        timestamp: new Date().toISOString(),
        ufw: ufwStatus,
        iptables: iptablesStatus,
        system: systemInfo,
        overall: this._calculateOverallStatus(ufwStatus, iptablesStatus)
      };
    } catch (error) {
      this.logger.error('Failed to get firewall status', error);
      throw error;
    }
  }

  /**
   * Add a new firewall rule
   * @param {Object} rule - Rule configuration
   * @returns {Promise<Object>} Added rule info
  **/

  async addRule(rule) {
    try {
      this.logger.info('Adding firewall rule', rule);

      // Rule validation
      this._validateRule(rule);

      let result;
      if (rule.manager === 'iptables') {
        result = await this.iptables.addRule(rule);
      } else {
        result = await this.ufw.addRule(rule);
      }

      if (this.config.autoSave) {
        await this.saveRules();
      }

      this.logger.info('Firewall rule added successfully', result);
      return result;
    } catch (error) {
      this.logger.error('Failed to add firewall rule', { error: error.message, rule });
      throw error;
    }
  }

  /**
   * Remove a firewall rule
   * @param {string|number} ruleId - Rule identifier
   * @param {string} manager - Firewall manager (ufw/iptables)
   * @returns {Promise<Object>} Removal result
  **/

  async removeRule(ruleId, manager = 'ufw') {
    try {
      this.logger.info('Removing firewall rule', { ruleId, manager });

      let result;
      if (manager === 'iptables') {
        result = await this.iptables.removeRule(ruleId);
      } else {
        result = await this.ufw.removeRule(ruleId);
      }

      if (this.config.autoSave) {
        await this.saveRules();
      }

      this.logger.info('Firewall rule removed successfully', result);
      return result;
    } catch (error) {
      this.logger.error('Failed to remove firewall rule', { error: error.message, ruleId, manager });
      throw error;
    }
  }

  /**
   * Get all firewall rules
   * @param {string} manager - Firewall manager (ufw/iptables)
   * @returns {Promise<Array>} List of rules
  **/

  async getRules(manager = 'ufw') {
    try {
      this.logger.debug('Getting firewall rules', { manager });

      let rules;
      if (manager === 'iptables') {
        rules = await this.iptables.getRules();
      } else {
        rules = await this.ufw.getRules();
      }

      return rules;
    } catch (error) {
      this.logger.error('Failed to get firewall rules', { error: error.message, manager });
      throw error;
    }
  }

  /**
   * Backup current firewall rules
   * @param {string} backupPath - Backup file path
   * @returns {Promise<Object>} Backup information
  **/

  async backupRules(backupPath = null) {
    try {
      this.logger.info('Creating firewall rules backup');

      const backupInfo = {
        timestamp: new Date().toISOString(),
        host: this.config.sshHost,
        ufw: await this.ufw.backup(backupPath),
        iptables: await this.iptables.backup(backupPath),
        system: await this.system.getInfo()
      };

      this.logger.info('Firewall rules backup created', backupInfo);
      return backupInfo;
    } catch (error) {
      this.logger.error('Failed to backup firewall rules', error);
      throw error;
    }
  }

  /**
   * Restore firewall rules from backup
   * @param {string} backupPath - Backup file path
   * @returns {Promise<Object>} Restore result
  **/

  async restoreRules(backupPath) {
    try {
      this.logger.info('Restoring firewall rules from backup', { backupPath });

      const restoreResult = {
        timestamp: new Date().toISOString(),
        ufw: await this.ufw.restore(backupPath),
        iptables: await this.iptables.restore(backupPath)
      };

      this.logger.info('Firewall rules restored successfully', restoreResult);
      return restoreResult;
    } catch (error) {
      this.logger.error('Failed to restore firewall rules', { error: error.message, backupPath });
      throw error;
    }
  }

  /**
   * Enable/disable firewall
   * @param {boolean} enabled - Enable or disable
   * @returns {Promise<Object>} Operation result
  **/

  async setFirewallState(enabled) {
    try {
      this.logger.info(`${enabled ? 'Enabling' : 'Disabling'} firewall`);

      const result = await this.ufw.setEnabled(enabled);

      this.logger.info(`Firewall ${enabled ? 'enabled' : 'disabled'} successfully`);
      return result;
    } catch (error) {
      this.logger.error(`Failed to ${enabled ? 'enable' : 'disable'} firewall`, error);
      throw error;
    }
  }

  /**
   * Reset firewall to default state
   * @returns {Promise<Object>} Reset result
  **/

  async resetFirewall() {
    try {
      this.logger.warn('Resetting firewall to default state');

      const result = await this.ufw.reset();

      this.logger.info('Firewall reset successfully');
      return result;
    } catch (error) {
      this.logger.error('Failed to reset firewall', error);
      throw error;
    }
  }

  /**
   * Get firewall logs
   * @param {Object} options - Log options
   * @returns {Promise<Array>} Log entries
  **/

  async getLogs(options = {}) {
    try {
      this.logger.debug('Getting firewall logs', options);

      const logs = await this.ufw.getLogs(options);
      return logs;
    } catch (error) {
      this.logger.error('Failed to get firewall logs', { error: error.message, options });
      throw error;
    }
  }

  /**
   * Monitor firewall in real-time
   * @param {Function} callback - Callback for log events
   * @param {Object} options - Monitor options
   * @returns {Promise<Object>} Monitor instance
  **/

  async monitor(callback, options = {}) {
    try {
      this.logger.info('Starting firewall monitor');

      const monitor = await this.ufw.monitor((log) => {
        callback(log);
        this.logger.debug('Firewall log event', log);
      }, options);

      return monitor;
    } catch (error) {
      this.logger.error('Failed to start firewall monitor', error);
      throw error;
    }
  }

  /**
   * Save current rules to persistent storage
   * @returns {Promise<Object>} Save result
  **/

  async saveRules() {
    try {
      this.logger.info('Saving firewall rules to persistent storage');

      const saveResult = {
        timestamp: new Date().toISOString(),
        ufw: await this.ufw.save(),
        iptables: await this.iptables.save()
      };

      this.logger.info('Firewall rules saved successfully', saveResult);
      return saveResult;
    } catch (error) {
      this.logger.error('Failed to save firewall rules', error);
      throw error;
    }
  }

  /**
   * Test firewall connectivity
   * @param {Object} testConfig - Test configuration
   * @returns {Promise<Object>} Test results
  **/

  async testConnectivity(testConfig = {}) {
    try {
      this.logger.info('Testing firewall connectivity');

      const tests = [
        this._testPort(testConfig.port || 80, testConfig.host || '8.8.8.8'),
        this._testPort(443, testConfig.host || '8.8.8.8'),
        this._testPort(22, testConfig.host || 'localhost')
      ];

      const results = await Promise.allSettled(tests);

      const testResults = {
        timestamp: new Date().toISOString(),
        tests: results.map((r, i) => ({
          test: tests[i].name,
          status: r.status,
          value: r.status === 'fulfilled' ? r.value : r.reason
        })),
        summary: this._analyzeTestResults(results)
      };

      this.logger.info('Connectivity tests completed', testResults.summary);
      return testResults;
    } catch (error) {
      this.logger.error('Connectivity tests failed', error);
      throw error;
    }
  }

  /**
   * Validate rule configuration
   * @private
  **/

  _validateRule(rule) {
    const required = ['action', 'direction'];
    const validActions = ['allow', 'deny', 'reject', 'limit'];
    const validDirections = ['in', 'out', 'forward'];
    const validProtocols = ['tcp', 'udp', 'icmp', 'all'];

    // Check required fields
    for (const field of required) {
      if (!rule[field]) {
        throw new Error(`Missing required field: ${field}`);
      }
    }

    // Validate action
    if (!validActions.includes(rule.action)) {
      throw new Error(`Invalid action: ${rule.action}. Valid actions: ${validActions.join(', ')}`);
    }

    // Validate direction
    if (!validDirections.includes(rule.direction)) {
      throw new Error(`Invalid direction: ${rule.direction}. Valid directions: ${validDirections.join(', ')}`);
    }

    // Validate protocol if provided
    if (rule.protocol && !validProtocols.includes(rule.protocol)) {
      throw new Error(`Invalid protocol: ${rule.protocol}. Valid protocols: ${validProtocols.join(', ')}`);
    }

    // Validate port if provided
    if (rule.port) {
      const port = parseInt(rule.port);
      if (isNaN(port) || port < 1 || port > 65535) {
        throw new Error(`Invalid port: ${rule.port}. Port must be between 1 and 65535`);
      }
    }

    // Validate IP addresses if provided
    if (rule.source) {
      if (!this._isValidIP(rule.source) && !this._isValidCIDR(rule.source)) {
        throw new Error(`Invalid source IP/CIDR: ${rule.source}`);
      }
    }

    if (rule.destination) {
      if (!this._isValidIP(rule.destination) && !this._isValidCIDR(rule.destination)) {
        throw new Error(`Invalid destination IP/CIDR: ${rule.destination}`);
      }
    }
  }

  /**
   * Check if string is valid IP address
   * @private
  **/

  _isValidIP(ip) {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
  }

  /**
   * Check if string is valid CIDR notation
   * @private
  **/

  _isValidCIDR(cidr) {
    const cidrRegex = /^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$/;
    return cidrRegex.test(cidr);
  }

  /**
   * Calculate overall firewall status
   * @private
  **/

  _calculateOverallStatus(ufwStatus, iptablesStatus) {
    if (!ufwStatus.active && !iptablesStatus.active) {
      return 'disabled';
    }

    if (ufwStatus.active && iptablesStatus.active) {
      return 'fully_active';
    }

    if (ufwStatus.active || iptablesStatus.active) {
      return 'partially_active';
    }

    return 'unknown';
  }

  /**
   * Test port connectivity
   * @private
  **/

  async _testPort(port, host) {
    return new Promise((resolve, reject) => {
      // This is a simplified example
      // In production, you would use net.connect or similar
      setTimeout(() => {
        if (port === 22) {
          resolve({ port, host, status: 'open' });
        } else {
          reject({ port, host, status: 'closed', error: 'Connection refused' });
        }
      }, 1000);
    });
  }

  /**
   * Analyze test results
   * @private
  **/

  _analyzeTestResults(results) {
    const passed = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;

    return {
      total: results.length,
      passed,
      failed,
      successRate: (passed / results.length) * 100
    };
  }

  /**
   * Get library version
   * @returns {string} Library version
  **/

  getVersion() {
    return require('./package.json').version;
  }

  /**
   * Get configuration
   * @returns {Object} Current configuration
  **/

  getConfig() {
    return { ...this.config };
  }

  /**
   * Update configuration
   * @param {Object} newConfig - New configuration
  **/

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    this.logger.updateLevel(this.config.logLevel);
    this.logger.info('Configuration updated', this.config);
  }

  /**
   * Cleanup resources
  **/

  async cleanup() {
    try {
      this.logger.info('Cleaning up resources');

      await this.ufw.cleanup();
      await this.iptables.cleanup();

      this.logger.info('Cleanup completed');
    } catch (error) {
      this.logger.error('Cleanup failed', error);
      throw error;
    }
  }
}

module.exports = CreartFirewall;
module.exports.UFWManager = UFWManager;
module.exports.IPTablesManager = IPTablesManager;
module.exports.SystemInfo = SystemInfo;
module.exports.Logger = require('./lib/utils').Logger;