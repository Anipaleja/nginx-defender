const axios = require('axios');
const { spawn } = require('child_process');
const EventEmitter = require('events');

/**
 * nginx-defender Node.js wrapper
 * 
 * Provides Node.js bindings for the nginx-defender WAF library.
 * 
 * @example
 * const { NginxDefender } = require('nginx-defender');
 * 
 * const defender = new NginxDefender();
 * await defender.start();
 * 
 * // Check if IP should be blocked
 * if (await defender.shouldBlock('192.168.1.100')) {
 *   // Handle blocking logic
 * }
 */
class NginxDefender extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            logLevel: 'info',
            dryRun: false,
            webUI: true,
            webUIPort: 8080,
            metricsPort: 9090,
            ...config
        };
        
        this.baseURL = `http://localhost:${this.config.webUIPort}`;
        this.isRunning = false;
        this.process = null;
    }
    
    /**
     * Start the nginx-defender service
     * @returns {Promise<boolean>} Success status
     */
    async start() {
        try {
            // Start the Go binary as a child process
            this.process = spawn('./nginx-defender-service', [
                '--api-mode',
                '--port', this.config.webUIPort.toString()
            ]);
            
            // Wait for service to be ready
            for (let i = 0; i < 30; i++) {
                try {
                    const response = await axios.get(`${this.baseURL}/health`, { timeout: 1000 });
                    if (response.status === 200) {
                        this.isRunning = true;
                        this.emit('started');
                        return true;
                    }
                } catch (error) {
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
            }
            
            return false;
        } catch (error) {
            this.emit('error', error);
            return false;
        }
    }
    
    /**
     * Stop the nginx-defender service
     */
    async stop() {
        if (this.process) {
            this.process.kill();
            this.process = null;
        }
        this.isRunning = false;
        this.emit('stopped');
    }
    
    /**
     * Check if an IP should be blocked
     * @param {string} ip - IP address to check
     * @returns {Promise<boolean>} Whether IP should be blocked
     */
    async shouldBlock(ip) {
        try {
            const response = await axios.post(`${this.baseURL}/api/check`, { ip }, { timeout: 5000 });
            return response.data.should_block || false;
        } catch (error) {
            return false;
        }
    }
    
    /**
     * Get threat score for an IP
     * @param {string} ip - IP address to check
     * @returns {Promise<number>} Threat score (0-100)
     */
    async getThreatScore(ip) {
        try {
            const response = await axios.post(`${this.baseURL}/api/check`, { ip }, { timeout: 5000 });
            return response.data.threat_score || 0;
        } catch (error) {
            return 0;
        }
    }
    
    /**
     * Block an IP address
     * @param {string} ip - IP to block
     * @param {number} durationMinutes - Block duration in minutes
     * @param {string} reason - Reason for blocking
     * @returns {Promise<boolean>} Success status
     */
    async blockIP(ip, durationMinutes = 60, reason = 'Manual block') {
        try {
            const response = await axios.post(`${this.baseURL}/api/block`, {
                ip,
                duration: `${durationMinutes}m`,
                reason
            }, { timeout: 5000 });
            
            if (response.status === 200) {
                this.emit('ipBlocked', { ip, duration: durationMinutes, reason });
                return true;
            }
            return false;
        } catch (error) {
            return false;
        }
    }
    
    /**
     * Unblock an IP address
     * @param {string} ip - IP to unblock
     * @returns {Promise<boolean>} Success status
     */
    async unblockIP(ip) {
        try {
            const response = await axios.post(`${this.baseURL}/api/unblock`, { ip }, { timeout: 5000 });
            if (response.status === 200) {
                this.emit('ipUnblocked', { ip });
                return true;
            }
            return false;
        } catch (error) {
            return false;
        }
    }
    
    /**
     * Monitor a log file for threats
     * @param {string} path - Path to log file
     * @param {string} format - Log format (combined, common, error, custom)
     * @returns {Promise<boolean>} Success status
     */
    async monitorLogFile(path, format = 'combined') {
        try {
            const response = await axios.post(`${this.baseURL}/api/monitor`, {
                path,
                format
            }, { timeout: 5000 });
            return response.status === 200;
        } catch (error) {
            return false;
        }
    }
    
    /**
     * Get current system metrics
     * @returns {Promise<Object>} Metrics data
     */
    async getMetrics() {
        try {
            const response = await axios.get(`${this.baseURL}/api/metrics`, { timeout: 5000 });
            return response.data || {};
        } catch (error) {
            return {};
        }
    }
}

/**
 * Express middleware for nginx-defender integration
 * @param {NginxDefender} defender - Defender instance
 * @returns {Function} Express middleware function
 */
function expressMiddleware(defender) {
    return async (req, res, next) => {
        const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
        
        try {
            if (await defender.shouldBlock(clientIP)) {
                return res.status(403).json({
                    error: 'Access denied',
                    message: 'Your IP has been blocked by our security system',
                    ip: clientIP
                });
            }
            
            // Add threat score to request
            req.threatScore = await defender.getThreatScore(clientIP);
            res.set('X-Protected-By', 'nginx-defender');
            
            next();
        } catch (error) {
            next(); // Continue on error to avoid breaking the app
        }
    };
}

/**
 * Koa middleware for nginx-defender integration
 * @param {NginxDefender} defender - Defender instance
 * @returns {Function} Koa middleware function
 */
function koaMiddleware(defender) {
    return async (ctx, next) => {
        const clientIP = ctx.ip;
        
        try {
            if (await defender.shouldBlock(clientIP)) {
                ctx.status = 403;
                ctx.body = {
                    error: 'Access denied',
                    message: 'Your IP has been blocked by our security system',
                    ip: clientIP
                };
                return;
            }
            
            // Add threat score to context
            ctx.threatScore = await defender.getThreatScore(clientIP);
            ctx.set('X-Protected-By', 'nginx-defender');
            
            await next();
        } catch (error) {
            await next(); // Continue on error
        }
    };
}

module.exports = {
    NginxDefender,
    expressMiddleware,
    koaMiddleware
};
