
import { v4 as uuidv4 } from 'uuid';
import { promises as fs } from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';
import WebSocket from 'ws';
import axios from 'axios';
import { getProviderModels } from '../provider-models.js';
import { configureAxiosProxy } from '../../utils/proxy-utils.js';
import { CredentialCacheManager } from '../../utils/credential-cache-manager.js';
import { countTokens as anthropicCountTokens } from '@anthropic-ai/tokenizer';

// ============================================================================
// 常量定义
// ============================================================================

const ORCHIDS_CONSTANTS = {
    API_BASE_URL: 'https://orchids-server.calmstone-6964e08a.westeurope.azurecontainerapps.io/',
    ORCHIDS_API_VERSION: '2',
    DEFAULT_ENDPOINT: 'coding-agent',
    CLERK_TOKEN_URL: 'https://clerk.orchids.app/v1/client/sessions/{sessionId}/tokens',
    CLERK_CLIENT_URL: 'https://clerk.orchids.app/v1/client',
    CLERK_JS_VERSION: '5.114.0',
    DEFAULT_TIMEOUT: 120000,
    USER_AGENT: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ORIGIN: 'https://www.orchids.app',
    DEFAULT_MODEL: 'claude-sonnet-4-5',
};

// Thinking 相关常量（参考 Kiro 实现）
const ORCHIDS_THINKING = {
    DEFAULT_BUDGET_TOKENS: 10000,
    MIN_BUDGET_TOKENS: 1024,
    MAX_BUDGET_TOKENS: 128000,
    MODE_TAG: '<thinking_mode>',
    MAX_LEN_TAG: '<max_thinking_length>',
};

// 从 provider-models.js 获取支持的模型列表
let ORCHIDS_MODELS;
try {
    ORCHIDS_MODELS = getProviderModels('claude-orchids-oauth');
} catch (e) {
    ORCHIDS_MODELS = ['claude-sonnet-4-5', 'claude-opus-4.5', 'claude-haiku-4-5', 'gemini-3-flash', 'gpt-5.2'];
}

// ============================================================================
// OrchidsApiService 类
// ============================================================================

/**
 * Orchids API Service - 通过 WebSocket 连接 Orchids 平台
 * 高可用模式：每次请求新建 WebSocket 连接，请求完成后立即关闭
 */
export class OrchidsApiService {
    constructor(config = {}) {
        this.isInitialized = false;
        this.config = config;
        this.credPath = config.ORCHIDS_CREDS_FILE_PATH;
        this.useSystemProxy = config?.USE_SYSTEM_PROXY_ORCHIDS ?? false;
        this.uuid = config?.uuid;
        
        console.log(`[Orchids] System proxy ${this.useSystemProxy ? 'enabled' : 'disabled'}`);
        
        // 认证相关
        this.clerkToken = null;
        this.tokenExpiresAt = null;
        this.cookies = null;
        this.clerkSessionId = null;
        this.userId = null;
        this.lastTokenRefreshTime = 0; // 上次 token 刷新时间戳
        
        // axios 实例
        this.axiosInstance = null;
        this.backgroundProcesses = new Map();
        
    }

    async initialize() {
        if (this.isInitialized) return;
        console.log('[Orchids] Initializing Orchids API Service...');
        
        await this.initializeAuth();
        
        const axiosConfig = {
            timeout: ORCHIDS_CONSTANTS.DEFAULT_TIMEOUT,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': ORCHIDS_CONSTANTS.USER_AGENT,
                'Origin': ORCHIDS_CONSTANTS.ORIGIN,
            },
        };
        
        if (!this.useSystemProxy) {
            axiosConfig.proxy = false;
        }
        
        configureAxiosProxy(axiosConfig, this.config, 'claude-orchids-oauth');
        
        this.axiosInstance = axios.create(axiosConfig);
        this.isInitialized = true;
        console.log('[Orchids] Initialization complete');
    }

    async initializeAuth(forceRefresh = false) {
        const credentialCache = CredentialCacheManager.getInstance();
        const providerType = 'claude-orchids-oauth';

        // 参考 simple_api.py 的实现：每次请求都重新获取 session
        // 因为 last_active_token 可能在使用后就失效

        if (!this.credPath) {
            throw new Error('[Orchids Auth] ORCHIDS_CREDS_FILE_PATH not configured');
        }

        try {
            // 优先从内存缓存加载
            let credentials = null;
            if (this.uuid && credentialCache.hasCredentials(providerType, this.uuid)) {
                const cachedEntry = credentialCache.getCredentials(providerType, this.uuid);
                if (cachedEntry && cachedEntry.credentials) {
                    credentials = cachedEntry.credentials;
                    console.log('[Orchids Auth] Loaded credentials from memory cache');
                }
            }

            // Fallback: 从文件加载
            if (!credentials) {
                const fileContent = await fs.readFile(this.credPath, 'utf8');
                credentials = JSON.parse(fileContent);
                console.log('[Orchids Auth] Loaded credentials from file');
            }

            this.clientJwt = credentials.clientJwt || credentials.client_jwt;

            if (!this.clientJwt && credentials.cookies) {
                this.clientJwt = this._extractClientJwtFromCookies(credentials.cookies);
            }

            if (!this.clientJwt) {
                throw new Error('[Orchids Auth] Missing required credential: clientJwt');
            }

            console.info(`[Orchids Auth] ${forceRefresh ? 'Refreshing' : 'Loading'} credentials from ${this.credPath}`);

            const sessionInfo = await this._getSessionFromClerk(this.clientJwt);

            if (sessionInfo) {
                this.clerkSessionId = sessionInfo.sessionId;
                this.userId = sessionInfo.userId;
                this.clerkToken = sessionInfo.wsToken;

                const jwtExpiry = this._parseJwtExpiry(this.clerkToken);
                if (jwtExpiry) {
                    this.tokenExpiresAt = jwtExpiry;
                } else {
                    this.tokenExpiresAt = new Date(Date.now() + 50 * 1000);
                }

                // 记录刷新时间，防止 ensureValidToken() 重复刷新
                this.lastTokenRefreshTime = Date.now();

                console.info(`[Orchids Auth] Session info obtained from Clerk API`);
                console.info(`[Orchids Auth]   Session ID: ${this.clerkSessionId}`);
                console.info(`[Orchids Auth]   User ID: ${this.userId}`);
                console.info(`[Orchids Auth]   Token expires at: ${this.tokenExpiresAt.toISOString()}`);
                console.info(`[Orchids Auth]   Token (first 50 chars): ${this.clerkToken?.substring(0, 50)}...`);
            } else {
                throw new Error('[Orchids Auth] Failed to get session info from Clerk API');
            }

        } catch (error) {
            if (error.code === 'ENOENT') {
                throw new Error(`[Orchids Auth] Credential file not found: ${this.credPath}`);
            }
            throw error;
        }
    }

    async _getSessionFromClerk(clientJwt) {
        try {
            const response = await axios.get(ORCHIDS_CONSTANTS.CLERK_CLIENT_URL, {
                headers: {
                    'Cookie': `__client=${clientJwt}`,
                    'Origin': ORCHIDS_CONSTANTS.ORIGIN,
                    'User-Agent': ORCHIDS_CONSTANTS.USER_AGENT,
                },
                timeout: 10000,
            });

            if (response.status !== 200) {
                console.error(`[Orchids Auth] Clerk API returned ${response.status}`);
                return null;
            }

            const data = response.data;
            const responseData = data.response || {};
            const sessions = responseData.sessions || [];

            if (sessions.length === 0) {
                console.error('[Orchids Auth] No active sessions found');
                return null;
            }

            const session = sessions[0];
            const sessionId = session.id;
            const userId = session.user?.id;
            const wsToken = session.last_active_token?.jwt;

            if (!sessionId || !wsToken) {
                console.error('[Orchids Auth] Invalid session data from Clerk API');
                return null;
            }

            return { sessionId, userId, wsToken };

        } catch (error) {
            console.error(`[Orchids Auth] Failed to get session from Clerk: ${error.message}`);
            return null;
        }
    }

    _extractClientJwtFromCookies(cookies) {
        if (!cookies) return null;
        const match = cookies.match(/__client=([^;]+)/);
        if (match && match[1]) {
            const jwt = match[1].trim();
            if (jwt.split('.').length === 3) {
                return jwt;
            }
        }
        return null;
    }

    _parseJwtExpiry(jwt) {
        if (!jwt) return null;
        
        try {
            const parts = jwt.split('.');
            if (parts.length !== 3) return null;
            
            const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
            
            if (payload.exp) {
                const expiryDate = new Date(payload.exp * 1000);
                console.debug(`[Orchids Auth] JWT expires at: ${expiryDate.toISOString()}`);
                return expiryDate;
            }
            
            return null;
        } catch (error) {
            console.warn(`[Orchids Auth] Failed to parse JWT expiry: ${error.message}`);
            return null;
        }
    }

    async _getFreshToken() {
        const tokenUrl = ORCHIDS_CONSTANTS.CLERK_TOKEN_URL
            .replace('{sessionId}', this.clerkSessionId) +
            `?_clerk_js_version=${ORCHIDS_CONSTANTS.CLERK_JS_VERSION}`;
        
        try {
            const response = await axios.post(tokenUrl, '', {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Cookie': this.cookies,
                    'Origin': ORCHIDS_CONSTANTS.ORIGIN,
                    'User-Agent': ORCHIDS_CONSTANTS.USER_AGENT,
                },
                timeout: 30000,
            });
            
            if (response.status === 200 && response.data?.jwt) {
                this.clerkToken = response.data.jwt;
                
                const jwtExpiry = this._parseJwtExpiry(this.clerkToken);
                if (jwtExpiry) {
                    this.tokenExpiresAt = jwtExpiry;
                    console.info(`[Orchids Auth] Token expires at: ${jwtExpiry.toISOString()}`);
                } else {
                    this.tokenExpiresAt = new Date(Date.now() + 50 * 1000);
                    console.warn('[Orchids Auth] Could not parse JWT expiry, using 50s fallback');
                }
                
                console.info('[Orchids Auth] Successfully obtained fresh token');
                await this._updateCredentialsFile();
                
                return this.clerkToken;
            } else {
                throw new Error(`Invalid token response: ${JSON.stringify(response.data)}`);
            }
        } catch (error) {
            console.error(`[Orchids Auth] Failed to get fresh token: ${error.message}`);
            throw error;
        }
    }

    async _updateCredentialsFile() {
        const credentialCache = CredentialCacheManager.getInstance();
        const providerType = 'claude-orchids-oauth';

        // 优先保存到内存缓存
        if (this.uuid && credentialCache.hasCredentials(providerType, this.uuid)) {
            const cachedEntry = credentialCache.getCredentials(providerType, this.uuid);
            if (cachedEntry && cachedEntry.credentials) {
                const updatedCredentials = {
                    ...cachedEntry.credentials,
                    expiresAt: this.tokenExpiresAt?.toISOString()
                };
                credentialCache.updateCredentials(providerType, this.uuid, updatedCredentials, this.credPath);
                console.debug('[Orchids Auth] Updated credentials in memory cache');
                return;
            }
        }

        // Fallback: 使用内存锁的文件写入
        await credentialCache.withMemoryLock(`orchids-update:${this.credPath}`, async () => {
            try {
                const fileContent = await fs.readFile(this.credPath, 'utf8');
                const credentials = JSON.parse(fileContent);
                credentials.expiresAt = this.tokenExpiresAt?.toISOString();
                await fs.writeFile(this.credPath, JSON.stringify(credentials, null, 2), 'utf8');
                console.debug('[Orchids Auth] Updated credentials file with new expiry');
            } catch (error) {
                console.warn(`[Orchids Auth] Failed to update credentials file: ${error.message}`);
            }
        });
    }

    // ========================================================================
    // Thinking 支持方法（参考 Kiro 实现）
    // ========================================================================

    /**
     * 规范化 thinking budget tokens
     * @param {number} budgetTokens - 原始 budget tokens 值
     * @returns {number} 规范化后的 budget tokens
     */
    _normalizeThinkingBudgetTokens(budgetTokens) {
        let value = Number(budgetTokens);
        if (!Number.isFinite(value) || value <= 0) {
            value = ORCHIDS_THINKING.DEFAULT_BUDGET_TOKENS;
        }
        value = Math.max(value, ORCHIDS_THINKING.MIN_BUDGET_TOKENS);
        value = Math.floor(value);
        return Math.min(value, ORCHIDS_THINKING.MAX_BUDGET_TOKENS);
    }

    /**
     * 生成 thinking 前缀
     * @param {object} thinking - thinking 配置对象
     * @returns {string|null} thinking 前缀字符串或 null
     */
    _generateThinkingPrefix(thinking) {
        if (!thinking || thinking.type !== 'enabled') return null;
        const budget = this._normalizeThinkingBudgetTokens(thinking.budget_tokens);
        return `<thinking_mode>enabled</thinking_mode><max_thinking_length>${budget}</max_thinking_length>`;
    }

    /**
     * 检查文本是否已包含 thinking 前缀
     * @param {string} text - 要检查的文本
     * @returns {boolean} 是否包含 thinking 前缀
     */
    _hasThinkingPrefix(text) {
        if (!text) return false;
        return text.includes(ORCHIDS_THINKING.MODE_TAG) || text.includes(ORCHIDS_THINKING.MAX_LEN_TAG);
    }

    _extractSystemPrompt(messages) {
        if (!messages || messages.length === 0) return '';
        
        const firstMessage = messages[0];
        if (firstMessage.role !== 'user') return '';
        
        const content = firstMessage.content;
        if (!Array.isArray(content)) return '';
        
        const systemPrompts = [];
        for (const block of content) {
            if (block.type === 'text') {
                const text = block.text || '';
                if (text.includes('<system-reminder>')) {
                    systemPrompts.push(text);
                }
            }
        }
        
        return systemPrompts.join('\n\n');
    }

    /**
     * 提取用户消息内容，保留 tool_result 的结构化信息
     * @param {Array} messages - 消息数组
     * @returns {Object} 包含 text 和 toolResults 的对象
     */
    _extractUserMessage(messages) {
        if (!messages || messages.length === 0) return { text: '', toolResults: [] };
        
        for (let i = messages.length - 1; i >= 0; i--) {
            const msg = messages[i];
            if (msg.role !== 'user') continue;
            
            const content = msg.content;
            if (typeof content === 'string') return { text: content, toolResults: [] };
            if (!Array.isArray(content)) continue;
            
            const textParts = [];
            const toolResults = [];
            
            for (const block of content) {
                if (block.type === 'text') {
                    const text = block.text || '';
                    if (!text.includes('<system-reminder>') && text.trim()) {
                        textParts.push(text);
                    }
                } else if (block.type === 'tool_result') {
                    // 保留结构化的 tool_result 信息（参考 Kiro 实现）
                    const toolResultContent = block.content || '';
                    const contentText = typeof toolResultContent === 'string' 
                        ? toolResultContent 
                        : JSON.stringify(toolResultContent);
                    
                    toolResults.push({
                        toolUseId: block.tool_use_id,
                        content: { text: contentText },
                        status: block.is_error ? 'error' : 'success'
                    });
                } else if (block.type === 'image') {
                    const mediaType = block.source?.media_type || block.media_type || 'unknown';
                    const sourceType = block.source?.type || 'unknown';
                    const sizeHint = block.source?.data ? ` bytes≈${Math.floor(block.source.data.length * 0.75)}` : '';
                    textParts.push(`[Image ${mediaType} ${sourceType}${sizeHint}]`);
                } else if (block.type === 'document') {
                    const sourceType = block.source?.type || 'unknown';
                    const sizeHint = block.source?.data ? ` bytes≈${Math.floor(block.source.data.length * 0.75)}` : '';
                    textParts.push(`[Document ${sourceType}${sizeHint}]`);
                }
            }
            
            const merged = textParts.join('\n').trim();
            if (merged || toolResults.length > 0) {
                return { text: merged, toolResults };
            }
            
            // Fallback: 尝试从最后一个 text block 获取内容
            for (let j = content.length - 1; j >= 0; j--) {
                const block = content[j];
                if (block.type === 'text') {
                    const text = block.text || '';
                    if (!text.includes('<system-reminder>') && text.trim()) {
                        return { text, toolResults: [] };
                    }
                }
            }
        }
        
        return { text: '', toolResults: [] };
    }

    /**
     * 将消息转换为聊天历史格式，保留 tool_result 的结构化信息
     * @param {Array} messages - 消息数组
     * @returns {Object} 包含 chatHistory 和 toolResults 的对象
     */
    _convertMessagesToChatHistory(messages) {
        const chatHistory = [];
        const allToolResults = [];
        
        for (const msg of messages) {
            const role = msg.role;
            const content = msg.content;
            
            if (role === 'user' && Array.isArray(content)) {
                const hasSystemReminder = content.some(
                    block => block.type === 'text' && (block.text || '').includes('<system-reminder>')
                );
                if (hasSystemReminder) continue;
            }
            
            if (role === 'user') {
                const textParts = [];
                const toolResults = [];
                
                if (typeof content === 'string') {
                    textParts.push(content);
                } else if (Array.isArray(content)) {
                    for (const block of content) {
                        if (block.type === 'text') {
                            textParts.push(block.text || '');
                        } else if (block.type === 'tool_result') {
                            // 保留结构化的 tool_result 信息（参考 Kiro 实现）
                            const toolResultContent = block.content || '';
                            const contentText = typeof toolResultContent === 'string' 
                                ? toolResultContent 
                                : JSON.stringify(toolResultContent);
                            
                            toolResults.push({
                                toolUseId: block.tool_use_id,
                                content: { text: contentText },
                                status: block.is_error ? 'error' : 'success'
                            });
                        } else if (block.type === 'image') {
                            const mediaType = block.source?.media_type || block.media_type || 'unknown';
                            const sourceType = block.source?.type || 'unknown';
                            textParts.push(`[Image ${mediaType} ${sourceType}]`);
                        } else if (block.type === 'document') {
                            const sourceType = block.source?.type || 'unknown';
                            textParts.push(`[Document ${sourceType}]`);
                        }
                    }
                }
                
                const text = textParts.join('\n');
                // 只有当有实际文本内容时才添加到 chatHistory
                // 空字符串会导致 Orchids API 报错 "The text field in the ContentBlock object is blank"
                if (text) {
                    chatHistory.push({ role: 'user', content: text });
                }
                // 收集所有 toolResults（无论是否有文本）
                if (toolResults.length > 0) {
                    allToolResults.push(...toolResults);
                }
            } else if (role === 'assistant') {
                const textParts = [];
                
                if (Array.isArray(content)) {
                    for (const block of content) {
                        if (block.type === 'text') {
                            textParts.push(block.text || '');
                        } else if (block.type === 'tool_use') {
                            const toolName = block.name || 'unknown';
                            const toolInput = block.input || {};
                            textParts.push(`[Used tool: ${toolName} with input: ${JSON.stringify(toolInput)}]`);
                        } else if (block.type === 'image') {
                            const mediaType = block.source?.media_type || block.media_type || 'unknown';
                            const sourceType = block.source?.type || 'unknown';
                            textParts.push(`[Image ${mediaType} ${sourceType}]`);
                        } else if (block.type === 'document') {
                            const sourceType = block.source?.type || 'unknown';
                            textParts.push(`[Document ${sourceType}]`);
                        }
                    }
                }
                
                const text = textParts.join('\n');
                if (text) {
                    chatHistory.push({ role: 'assistant', content: text });
                }
            }
        }
        
        return { chatHistory, toolResults: allToolResults };
    }

    /**
     * 解析文本中的工具调用（支持多种格式）
     * @param {string} text - 要解析的文本
     * @param {Array} clientToolIndex - 客户端工具索引
     * @returns {Array|null} 解析出的工具调用数组或 null
     */
    _parseTextToolCalls(text, clientToolIndex = []) {
        if (!text || typeof text !== 'string') return null;

        // 多种工具调用模式匹配
        const patterns = [
            // 标准格式：[Used tool: toolName with input: {...}]
            /\[Used tool:\s*([^\s]+)\s+with input:\s*(\{[^}]*\}|\{[\s\S]*?\})\]/g,
            // 简化格式：[toolName: {...}]
            /\[([a-zA-Z_][a-zA-Z0-9_-]*?):\s*(\{[^}]*\}|\{[\s\S]*?\})\]/g,
            // 函数调用格式：toolName({...})
            /([a-zA-Z_][a-zA-Z0-9_-]*?)\s*\(\s*(\{[^}]*\}|\{[\s\S]*?\})\s*\)/g
        ];

        const toolCalls = [];
        const seenCalls = new Set(); // 防重复

        for (const pattern of patterns) {
            let match;
            while ((match = pattern.exec(text)) !== null) {
                const [, orToolName, inputStr] = match;

                // 防重复：基于完整匹配内容去重
                const callKey = `${orToolName}:${inputStr}`;
                if (seenCalls.has(callKey)) continue;
                seenCalls.add(callKey);

                try {
                    const toolInput = JSON.parse(inputStr);
                    const clientToolName = this._mapToolNameToClient(orToolName, toolInput, clientToolIndex);

                    const toolCallId = `call_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;

                    toolCalls.push({
                        id: toolCallId,
                        type: 'function',
                        function: {
                            name: clientToolName,
                            arguments: JSON.stringify(toolInput)
                        }
                    });

                    console.log(`[Orchids] Mapped tool from text: ${orToolName} -> ${clientToolName}`);

                } catch (error) {
                    console.warn(`[Orchids] Failed to parse tool input for ${orToolName}:`, error.message);
                    continue;
                }
            }
        }

        return toolCalls.length > 0 ? toolCalls : null;
    }

    _extractAttachmentUrls(messages) {
        const urls = [];
        for (const msg of messages || []) {
            const content = msg?.content;
            if (!Array.isArray(content)) continue;
            for (const block of content) {
                if (!block) continue;
                if (block.type !== 'image' && block.type !== 'document') continue;
                const url = block.source?.url || block.url;
                if (typeof url === 'string' && url.trim()) {
                    urls.push(url.trim());
                }
            }
        }
        return [...new Set(urls)];
    }

    _normalizeToolName(name) {
        const raw = String(name || '').trim();
        if (!raw) return { raw: '', lowered: '', short: '' };
        const lowered = raw.toLowerCase();
        const parts = raw.split(/[./:]+/).filter(Boolean);
        const short = (parts[parts.length - 1] || raw).toLowerCase();
        return { raw, lowered, short };
    }

    _buildClientToolIndex(tools) {
        if (!Array.isArray(tools)) return [];
        return tools
            .filter((t) => t && typeof t.name === 'string' && t.name.trim())
            .map((t) => {
                const normalized = this._normalizeToolName(t.name);
                const props = t.input_schema?.properties && typeof t.input_schema.properties === 'object'
                    ? new Set(Object.keys(t.input_schema.properties))
                    : new Set();
                return {
                    name: t.name,
                    normalized,
                    props,
                };
            });
    }

    _mapToolNameToClient(orToolName, toolInput, clientToolIndex) {
        const index = Array.isArray(clientToolIndex) ? clientToolIndex : [];
        const normalized = this._normalizeToolName(orToolName);
        if (!normalized.raw || index.length === 0) return normalized.raw || orToolName;

        const exact = index.find((t) => t.name === normalized.raw);
        if (exact) return exact.name;

        const ci = index.find((t) => t.normalized.lowered === normalized.lowered);
        if (ci) return ci.name;

        const byShort = index.find((t) => t.normalized.short === normalized.short);
        if (byShort) return byShort.name;

        // 扩展的工具别名映射
        const aliasCandidates = {
            ripgrep: ['grep', 'ripgrep', 'search_files'],
            glob: ['glob', 'list_files'],
            read: ['read', 'readfile', 'read_file', 'view'],
            write: ['write', 'writefile', 'write_file', 'create_file', 'createfile', 'save-file'],
            edit: ['edit', 'editfile', 'edit_file', 'str-replace-editor', 'apply_diff'],
            run_command: ['runcommand', 'run_command', 'bash', 'execute_command', 'launch-process'],
            delete: ['delete', 'delete_file', 'remove-files'],
            // 新增 Orchids 特有的工具映射
            ask_followup_question: ['ask_followup_question', 'ask'],
            attempt_completion: ['attempt_completion', 'complete'],
            switch_mode: ['switch_mode', 'mode_switch'],
            update_todo_list: ['update_todo_list', 'todo'],
            new_task: ['new_task', 'task'],
            fetch_instructions: ['fetch_instructions', 'instructions'],
            // MCP 工具映射
            'mcp--playwright--browser_navigate': ['browser_navigate', 'navigate'],
            'mcp--playwright--browser_click': ['browser_click', 'click'],
            'mcp--playwright--browser_type': ['browser_type', 'type'],
            'mcp--playwright--browser_snapshot': ['browser_snapshot', 'snapshot'],
            'mcp--playwright--browser_take_screenshot': ['browser_take_screenshot', 'screenshot'],
        };

        // 首先尝试直接别名匹配
        const aliasKeys = aliasCandidates[normalized.short];
        if (aliasKeys) {
            const hit = index.find((t) => aliasKeys.includes(t.normalized.short));
            if (hit) return hit.name;
        }

        // 反向查找：如果 Orchids 工具名在客户端工具的别名中
        for (const clientTool of index) {
            const clientAliases = aliasCandidates[clientTool.normalized.short] || [];
            if (clientAliases.includes(normalized.short) || clientAliases.includes(normalized.lowered)) {
                return clientTool.name;
            }
        }

        // 基于输入参数的智能匹配
        if (toolInput && typeof toolInput === 'object' && !Array.isArray(toolInput)) {
            const inputKeys = Object.keys(toolInput);
            if (inputKeys.length > 0) {
                const candidates = index
                    .map((t) => {
                        if (!t.props || t.props.size === 0) return null;
                        const hasAll = inputKeys.every((k) => t.props.has(k));
                        if (!hasAll) return null;
                        const score = inputKeys.reduce((acc, k) => acc + (t.props.has(k) ? 1 : 0), 0);
                        return { name: t.name, score, extra: t.props.size - score };
                    })
                    .filter(Boolean)
                    .sort((a, b) => (b.score - a.score) || (a.extra - b.extra));
                if (candidates.length > 0) return candidates[0].name;
            }
        }

        return normalized.raw;
    }

    async _convertToOrchidsRequest(model, claudeRequest, thinking = null, tools = null) {
        const messages = claudeRequest.messages || [];
        
        const systemPrompt = this._extractSystemPrompt(messages);
        // _extractUserMessage 现在返回 { text, toolResults } 对象
        const userMessageResult = this._extractUserMessage(messages);
        const userMessage = userMessageResult.text;
        const currentToolResults = userMessageResult.toolResults;
        
        // ========================================================================
        // 工具定义转换（参考 Kiro 实现）
        // ========================================================================
        let orchidsTools = null;
        if (tools && Array.isArray(tools) && tools.length > 0) {
            // 过滤掉 web_search 或 websearch 工具（忽略大小写）
            const filteredTools = tools.filter(tool => {
                const name = (tool.name || '').toLowerCase();
                const shouldIgnore = name === 'web_search' || name === 'websearch';
                if (shouldIgnore) {
                    console.log(`[Orchids] Ignoring tool: ${tool.name}`);
                }
                return !shouldIgnore;
            });
            
            if (filteredTools.length === 0) {
                // 所有工具都被过滤掉了，不添加 tools 上下文
                console.log('[Orchids] All tools were filtered out');
            } else {
                const MAX_DESCRIPTION_LENGTH = 9216;
                
                let truncatedCount = 0;
                orchidsTools = filteredTools.map(tool => {
                    let desc = tool.description || '';
                    const originalLength = desc.length;
                    
                    if (desc.length > MAX_DESCRIPTION_LENGTH) {
                        desc = desc.substring(0, MAX_DESCRIPTION_LENGTH) + '...';
                        truncatedCount++;
                        console.log(`[Orchids] Truncated tool '${tool.name}' description: ${originalLength} -> ${desc.length} chars`);
                    }
                    
                    return {
                        toolSpecification: {
                            name: tool.name,
                            description: desc,
                            inputSchema: {
                                json: tool.input_schema || {}
                            }
                        }
                    };
                });
                
                if (truncatedCount > 0) {
                    console.log(`[Orchids] Truncated ${truncatedCount} tool description(s) to max ${MAX_DESCRIPTION_LENGTH} chars`);
                }
                
                console.log(`[Orchids] Converted ${orchidsTools.length} tools for request`);
            }
        }
        
        // 生成 thinking 前缀
        const thinkingPrefix = this._generateThinkingPrefix(thinking);
        
        const isUserInputMessage = (msg) => {
            if (!msg || msg.role !== 'user') return false;
            const content = msg.content;
            if (typeof content === 'string') return content.trim().length > 0;
            if (!Array.isArray(content)) return false;
            return content.some(block => {
                if (!block) return false;
                if (block.type === 'tool_result') return true;
                if (block.type === 'text') {
                    const text = block.text || '';
                    return !text.includes('<system-reminder>') && text.trim().length > 0;
                }
                if (block.type === 'image' || block.type === 'document') return true;
                return false;
            });
        };
        
        let currentUserMsgIndex = -1;
        for (let i = messages.length - 1; i >= 0; i--) {
            if (isUserInputMessage(messages[i])) {
                currentUserMsgIndex = i;
                break;
            }
        }
        
        // _convertMessagesToChatHistory 现在返回 { chatHistory, toolResults } 对象
        const historyResult = currentUserMsgIndex >= 0
            ? this._convertMessagesToChatHistory(messages.slice(0, currentUserMsgIndex))
            : this._convertMessagesToChatHistory(messages);
        
        const chatHistory = historyResult.chatHistory;
        const historyToolResults = historyResult.toolResults;
        
        // 合并所有 toolResults（历史 + 当前消息）
        const allToolResults = [...historyToolResults, ...currentToolResults];
        
        // 去重 toolResults - 参考 Kiro 实现，API 不接受重复的 toolUseId
        const uniqueToolResults = [];
        const seenIds = new Set();
        for (const tr of allToolResults) {
            if (!seenIds.has(tr.toolUseId)) {
                seenIds.add(tr.toolUseId);
                uniqueToolResults.push(tr);
            }
        }
        
        if (uniqueToolResults.length > 0) {
            console.log(`[Orchids] Collected ${uniqueToolResults.length} tool result(s) for request`);
        }
        
        const now = new Date();
        const dateStr = now.toISOString().split('T')[0];
        
        // 构建 prompt，如果有 thinking 前缀则注入到开头
        const promptContent = `
<context>
You are Claude, an AI assistant by Anthropic, helping users through a general-purpose API interface. This interface supports various programming languages and tasks beyond any specific framework.
</context>

<environment>
Date: ${dateStr}
Interface: General API (supports all languages and frameworks)
</environment>

<guidelines>
- Respond in the same language the user uses (e.g., Chinese input → Chinese response).
- Focus on the user's actual request without assumptions about their tech stack.
- For coding tasks, support any language or framework the user is working with.
</guidelines>

<tone_and_style>
- Be concise and direct. Eliminate unnecessary filler, pleasantries, or robotic intros (e.g., avoid "As an AI..." or "I can help with that").
- Answer the user's question immediately without restating it.
- Maintain a professional, objective, and neutral tone.
- Avoid preaching or moralizing; focus purely on the technical or factual aspects of the request.
</tone_and_style>

${systemPrompt ? `<system_context>\n${systemPrompt}\n</system_context>\n` : ''}

<user_message>
${userMessage}
</user_message>
`;
        
        // 如果有 thinking 前缀且 prompt 中尚未包含，则注入到开头
        const prompt = (thinkingPrefix && !this._hasThinkingPrefix(promptContent))
            ? thinkingPrefix + '\n' + promptContent
            : promptContent;
        
        return {
            type: 'user_request',
            data: {
                projectId: null,
                chatSessionId: `chat_${uuidv4().replace(/-/g, '').slice(0, 12)}`,
                prompt: prompt,
                agentMode: model || ORCHIDS_CONSTANTS.DEFAULT_MODEL,
                mode: 'agent',
                chatHistory: chatHistory,
                attachmentUrls: this._extractAttachmentUrls(messages),
                currentPage: null,
                email: 'bridge@localhost',
                isLocal: Boolean(this.config?.ORCHIDS_LOCAL_WORKDIR),
                isFixingErrors: false,
                localWorkingDirectory: this.config?.ORCHIDS_LOCAL_WORKDIR || undefined,
                fileStructure: undefined,
                userId: this.userId || 'local_user',
                // 工具定义（如果有）
                ...(orchidsTools && orchidsTools.length > 0 ? { tools: orchidsTools } : {}),
                // 工具结果（如果有）- 参考 Kiro 实现
                ...(uniqueToolResults.length > 0 ? { toolResults: uniqueToolResults } : {}),
            },
        };
    }

    /**
     * 发送 fs_operation_response 到 WebSocket
     * 参考 simple_api.py 的实现：收到 fs_operation 后需要返回响应，否则 Orchids 会一直等待
     */
    _createFsOperationResponse(opId, success = true, data = null, error = undefined) {
        return {
            type: 'fs_operation_response',
            id: opId,
            success: success,
            data: data,
            error: error,
        };
    }

    _getAgentWsBaseUrl() {
        const configured = this.config?.ORCHIDS_WS_BASE_URL;
        if (configured && typeof configured === 'string') {
            return configured.replace(/\/$/, '');
        }
        const apiBase = (this.config?.ORCHIDS_API_BASE_URL || ORCHIDS_CONSTANTS.API_BASE_URL).replace(/\/$/, '');
        const wsBase = apiBase.replace(/^http/, 'ws');
        return `${wsBase}/agent/ws`;
    }

    _buildAgentWsUrl(endpoint = ORCHIDS_CONSTANTS.DEFAULT_ENDPOINT) {
        const base = this._getAgentWsBaseUrl();
        const version = this.config?.ORCHIDS_API_VERSION || ORCHIDS_CONSTANTS.ORCHIDS_API_VERSION;
        const token = this.clerkToken || '';
        return `${base}/${endpoint}?token=${encodeURIComponent(token)}&orchids_api_version=${encodeURIComponent(version)}`;
    }

    _resolveFsPath(inputPath, workingDirectory) {
        if (!inputPath) return inputPath;
        if (typeof inputPath !== 'string') return inputPath;
        if (/^[a-zA-Z]:[\\/]/.test(inputPath) || inputPath.startsWith('\\\\')) return inputPath;
        if (inputPath.startsWith('/')) return inputPath;
        if (!workingDirectory) return inputPath;
        return path.join(workingDirectory, inputPath);
    }

    async _handleFsOperation(ws, message, workingDirectory) {
        const opId = message.id;
        const operation = message.operation || '';
        const filePath = this._resolveFsPath(message.path, workingDirectory);
        const content = message.content;
        const command = message.command;

        const send = (payload) => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(payload));
            }
        };

        try {
            switch (operation) {
                case 'read': {
                    if (!filePath) {
                        send(this._createFsOperationResponse(opId, false, null, 'Path is required for read operation'));
                        return;
                    }
                    const text = await fs.readFile(filePath, 'utf8');
                    send(this._createFsOperationResponse(opId, true, text));
                    return;
                }
                case 'write': {
                    if (!filePath) {
                        send(this._createFsOperationResponse(opId, false, null, 'Path is required for write operation'));
                        return;
                    }
                    if (content === undefined) {
                        send(this._createFsOperationResponse(opId, false, null, 'Content is required for write operation'));
                        return;
                    }
                    await fs.mkdir(path.dirname(filePath), { recursive: true });
                    await fs.writeFile(filePath, String(content), 'utf8');
                    send(this._createFsOperationResponse(opId, true, null));
                    return;
                }
                case 'delete': {
                    if (!filePath) {
                        send(this._createFsOperationResponse(opId, false, null, 'Path is required for delete operation'));
                        return;
                    }
                    await fs.rm(filePath, { recursive: true, force: true });
                    send(this._createFsOperationResponse(opId, true, null));
                    return;
                }
                case 'list': {
                    const toList = filePath || workingDirectory || '.';
                    const entries = await fs.readdir(toList);
                    send(this._createFsOperationResponse(opId, true, entries));
                    return;
                }
                case 'run_command': {
                    if (!command) {
                        send(this._createFsOperationResponse(opId, false, null, 'Command is required for run_command operation'));
                        return;
                    }
                    const allow = this.config?.ORCHIDS_ALLOW_RUN_COMMAND === true;
                    if (!allow) {
                        send(this._createFsOperationResponse(opId, false, null, 'run_command is disabled by server config'));
                        return;
                    }
                    const isBackground = message.is_background === true;
                    const bashId = message.bash_id || `bash_${uuidv4().replace(/-/g, '').slice(0, 12)}`;
                    const cwd = workingDirectory || process.cwd();

                    if (isBackground) {
                        const proc = spawn(command, {
                            cwd,
                            shell: true,
                            windowsHide: true,
                        });

                        const record = {
                            bashId,
                            proc,
                            output: '',
                            exited: false,
                            exitCode: null,
                        };
                        this.backgroundProcesses.set(bashId, record);

                        proc.stdout?.on('data', (buf) => {
                            record.output += buf.toString();
                        });
                        proc.stderr?.on('data', (buf) => {
                            record.output += buf.toString();
                        });
                        proc.on('close', (code) => {
                            record.exited = true;
                            record.exitCode = code;
                        });

                        send(this._createFsOperationResponse(opId, true, `Started background process: ${bashId}`));
                        return;
                    }

                    const proc = spawn(command, {
                        cwd,
                        shell: true,
                        windowsHide: true,
                    });

                    let output = '';
                    proc.stdout?.on('data', (buf) => {
                        output += buf.toString();
                    });
                    proc.stderr?.on('data', (buf) => {
                        output += buf.toString();
                    });

                    const exitCode = await new Promise((resolve, reject) => {
                        proc.on('error', reject);
                        proc.on('close', resolve);
                    });

                    if (exitCode === 0) {
                        send(this._createFsOperationResponse(opId, true, output));
                    } else {
                        send(this._createFsOperationResponse(opId, false, output, `Command failed with exit code ${exitCode}`));
                    }
                    return;
                }
                case 'get_background_output': {
                    const bashId = message.bash_id;
                    if (!bashId) {
                        send(this._createFsOperationResponse(opId, false, null, 'bash_id is required for get_background_output operation'));
                        return;
                    }
                    const record = this.backgroundProcesses.get(bashId);
                    if (!record) {
                        send(this._createFsOperationResponse(opId, false, null, `Unknown bash_id: ${bashId}`));
                        return;
                    }
                    send(this._createFsOperationResponse(opId, true, record.output));
                    return;
                }
                case 'kill_background_process': {
                    const bashId = message.bash_id;
                    if (!bashId) {
                        send(this._createFsOperationResponse(opId, false, null, 'bash_id is required for kill_background_process operation'));
                        return;
                    }
                    const record = this.backgroundProcesses.get(bashId);
                    if (!record) {
                        send(this._createFsOperationResponse(opId, false, null, `Unknown bash_id: ${bashId}`));
                        return;
                    }
                    try {
                        record.proc.kill();
                        this.backgroundProcesses.delete(bashId);
                        send(this._createFsOperationResponse(opId, true, `Killed background process: ${bashId}`));
                    } catch (e) {
                        send(this._createFsOperationResponse(opId, false, null, e?.message || 'Failed to kill background process'));
                    }
                    return;
                }
                case 'glob': {
                    const params = message.globParameters || {};
                    const pattern = params.pattern || params.glob || '';
                    const root = this._resolveFsPath(params.path || workingDirectory || '.', workingDirectory) || '.';
                    const maxResults = Number.isFinite(params.maxResults) ? params.maxResults : 500;
                    const matches = await this._globSearch(root, pattern, maxResults);
                    send(this._createFsOperationResponse(opId, true, matches));
                    return;
                }
                case 'ripgrep': {
                    const params = message.ripgrepParameters || {};
                    const output = await this._ripgrepSearch(params, workingDirectory);
                    send(this._createFsOperationResponse(opId, true, output));
                    return;
                }
                case 'get_terminal_logs': {
                    send(this._createFsOperationResponse(opId, true, ''));
                    return;
                }
                case 'get_browser_logs': {
                    send(this._createFsOperationResponse(opId, true, ''));
                    return;
                }
                case 'update_startup_commands': {
                    send(this._createFsOperationResponse(opId, true, null));
                    return;
                }
                case 'create_terminal':
                case 'kill_terminal':
                default: {
                    send(this._createFsOperationResponse(opId, false, null, `Unknown operation: ${operation}`));
                }
            }
        } catch (error) {
            send(this._createFsOperationResponse(opId, false, null, error?.message || 'Unknown error'));
        }
    }

    _globToRegExp(globPattern) {
        const pattern = String(globPattern || '').replace(/\\/g, '/');
        let re = '^';
        for (let i = 0; i < pattern.length; i++) {
            const ch = pattern[i];
            if (ch === '*') {
                const next = pattern[i + 1];
                if (next === '*') {
                    const nextNext = pattern[i + 2];
                    if (nextNext === '/') {
                        re += '(?:.*/)?';
                        i += 2;
                    } else {
                        re += '.*';
                        i++;
                    }
                } else {
                    re += '[^/]*';
                }
            } else if (ch === '?') {
                re += '[^/]';
            } else {
                re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
            }
        }
        re += '$';
        return new RegExp(re);
    }

    async _globSearch(rootPath, globPattern, maxResults) {
        if (!globPattern) return [];
        const matcher = this._globToRegExp(globPattern);
        const root = path.resolve(rootPath);
        const results = [];
        const stack = [root];

        while (stack.length > 0 && results.length < maxResults) {
            const current = stack.pop();
            let entries;
            try {
                entries = await fs.readdir(current, { withFileTypes: true });
            } catch {
                continue;
            }
            for (const entry of entries) {
                if (results.length >= maxResults) break;
                const fullPath = path.join(current, entry.name);
                const relative = path.relative(root, fullPath).replace(/\\/g, '/');
                if (entry.isDirectory()) {
                    if (entry.name !== 'node_modules' && entry.name !== '.git') {
                        stack.push(fullPath);
                    }
                } else if (entry.isFile()) {
                    if (matcher.test(relative)) {
                        results.push(fullPath);
                    }
                }
            }
        }

        return results;
    }

    async _collectFilesFromPaths(pathsInput, workingDirectory, maxFiles) {
        const startPaths = Array.isArray(pathsInput) && pathsInput.length > 0 ? pathsInput : [workingDirectory || '.'];
        const results = [];
        const visited = new Set();
        const stack = startPaths
            .filter(Boolean)
            .map(p => path.resolve(this._resolveFsPath(p, workingDirectory) || p));

        while (stack.length > 0 && results.length < maxFiles) {
            const current = stack.pop();
            if (!current || visited.has(current)) continue;
            visited.add(current);

            let stat;
            try {
                stat = await fs.stat(current);
            } catch {
                continue;
            }

            if (stat.isDirectory()) {
                let entries;
                try {
                    entries = await fs.readdir(current, { withFileTypes: true });
                } catch {
                    continue;
                }
                for (const entry of entries) {
                    if (entry.name === 'node_modules' || entry.name === '.git') continue;
                    stack.push(path.join(current, entry.name));
                }
            } else if (stat.isFile()) {
                results.push(current);
            }
        }

        return results;
    }

    async _ripgrepSearch(params, workingDirectory) {
        const query = String(params.query || '');
        if (!query) return '';

        const maxResults = Number.isFinite(params.maxResults) ? params.maxResults : 200;
        const maxFiles = Number.isFinite(params.maxFiles) ? params.maxFiles : 5000;
        const caseInsensitive = params.caseInsensitive === true;
        const isRegex = params.isRegex === true;

        let regexp = null;
        if (isRegex) {
            try {
                regexp = new RegExp(query, caseInsensitive ? 'i' : undefined);
            } catch {
                regexp = null;
            }
        }

        const files = await this._collectFilesFromPaths(params.paths, workingDirectory, maxFiles);
        let found = 0;
        const linesOut = [];

        for (const filePath of files) {
            if (found >= maxResults) break;
            let stat;
            try {
                stat = await fs.stat(filePath);
            } catch {
                continue;
            }
            if (stat.size > 2 * 1024 * 1024) continue;

            let text;
            try {
                text = await fs.readFile(filePath, 'utf8');
            } catch {
                continue;
            }

            const lines = text.split(/\r?\n/);
            for (let i = 0; i < lines.length; i++) {
                if (found >= maxResults) break;
                const line = lines[i];
                let idx = -1;
                if (regexp) {
                    const m = regexp.exec(line);
                    if (m) idx = m.index;
                } else {
                    const hay = caseInsensitive ? line.toLowerCase() : line;
                    const needle = caseInsensitive ? query.toLowerCase() : query;
                    idx = hay.indexOf(needle);
                }
                if (idx >= 0) {
                    found++;
                    linesOut.push(`${filePath}:${i + 1}:${idx + 1}:${line}`);
                }
            }
        }

        return linesOut.join('\n');
    }

    _convertToAnthropicSSE(orchidsMessage, state) {
        const msgType = orchidsMessage.type;
        const events = [];
        // 默认启用工具调用输出，与 Kiro 行为一致
        const emitToolUse = this.config?.ORCHIDS_EMIT_TOOL_USE !== false;

        // ========================================================================
        // 注意：Orchids API 会同时发送两种事件流：
        // 1. model 事件 - 底层模型事件（reasoning-delta, text-delta 等）
        // 2. coding_agent.* 事件 - 高层代理事件（reasoning.chunk, output_text_delta 等）
        //
        // 这两种事件包含相同的内容，为避免重复处理导致叠字，
        // 我们优先处理 coding_agent 事件，完全忽略对应的 model 事件
        // ========================================================================

        // 处理 coding_agent 推理事件
        if (msgType === 'coding_agent.reasoning.chunk') {
            state.preferCodingAgentEvents = true; // 标记优先使用 coding_agent 事件
            const chunk = orchidsMessage.data || orchidsMessage.chunk;
            const text = typeof chunk === 'string' ? chunk : (chunk?.text || chunk?.content || '');
            if (text && !state.reasoningStarted) {
                state.reasoningStarted = true;
                state.currentBlockIndex = 0;
                events.push({
                    type: 'content_block_start',
                    index: 0,
                    content_block: {
                        type: 'thinking',
                        thinking: '',
                    },
                });
            }
            if (text && state.reasoningStarted) {
                return {
                    type: 'content_block_delta',
                    index: 0,
                    delta: {
                        type: 'thinking_delta',
                        thinking: text,
                    },
                };
            }
            return null;
        }

        if (msgType === 'coding_agent.reasoning.completed') {
            state.preferCodingAgentEvents = true;
            if (state.reasoningStarted && !state.reasoningEnded) {
                state.reasoningEnded = true;
                events.push({
                    type: 'content_block_stop',
                    index: 0,
                });
            }
            return events.length > 0 ? events : null;
        }

        // 处理 coding_agent 输出文本事件
        if (msgType === 'output_text_delta') {
            state.preferCodingAgentEvents = true; // 标记优先使用 coding_agent 事件
            const text = orchidsMessage.delta || orchidsMessage.text || '';
            if (text) {
                // 累积文本用于后续解析工具调用
                state.accumulatedText += text;

                if (!state.responseStarted) {
                    state.responseStarted = true;
                    state.currentBlockIndex = state.reasoningStarted ? 1 : 0;
                    state.textBlockClosed = false;
                    events.push({
                        type: 'content_block_start',
                        index: state.currentBlockIndex,
                        content_block: {
                            type: 'text',
                            text: '',
                        },
                    });
                }

                // 发送文本增量事件
                events.push({
                    type: 'content_block_delta',
                    index: state.currentBlockIndex,
                    delta: {
                        type: 'text_delta',
                        text: text,
                    },
                });
            }
            return events.length > 0 ? events : null;
        }
        
        // ========================================================================
        // 处理 model 事件（底层模型事件）- 只在没有 coding_agent 事件时处理
        // ========================================================================
        if (msgType === 'model') {
            const event = orchidsMessage.event || {};
            const eventType = event.type || '';

            // 如果已经有 coding_agent 事件，跳过 model 事件以避免重复
            if (state.preferCodingAgentEvents) {
                return null;
            }

            // --------------------------------------------------------------------
            // 处理 reasoning 事件（模型级别的思考）
            // --------------------------------------------------------------------
            if (eventType === 'reasoning-start') {
                if (!state.reasoningStarted) {
                    state.reasoningStarted = true;
                    state.currentBlockIndex = 0;
                    events.push({
                        type: 'content_block_start',
                        index: 0,
                        content_block: {
                            type: 'thinking',
                            thinking: '',
                        },
                    });
                }
                return events.length > 0 ? events : null;
            }

            if (eventType === 'reasoning-delta') {
                const text = event.delta || '';
                if (text && state.reasoningStarted) {
                    return {
                        type: 'content_block_delta',
                        index: 0,
                        delta: {
                            type: 'thinking_delta',
                            thinking: text,
                        },
                    };
                }
                return null;
            }

            if (eventType === 'reasoning-end') {
                if (state.reasoningStarted && !state.reasoningEnded) {
                    state.reasoningEnded = true;
                    events.push({
                        type: 'content_block_stop',
                        index: 0,
                    });
                }
                return events.length > 0 ? events : null;
            }
            
            // --------------------------------------------------------------------
            // 处理 tool-input 事件（工具调用）
            // 这是 Orchids 原生工具调用的核心事件
            // --------------------------------------------------------------------
            if (eventType === 'tool-input-start') {
                if (!emitToolUse) return null;
                const toolCallId = event.id || `toolu_${uuidv4().replace(/-/g, '').substring(0, 12)}`;
                const toolName = event.toolName || 'unknown';
                const mappedToolName = this._mapToolNameToClient(toolName, null, state.clientToolIndex);

                // 关闭之前的文本块（如果有）
                if (state.responseStarted && !state.textBlockClosed) {
                    events.push({
                        type: 'content_block_stop',
                        index: state.currentBlockIndex,
                    });
                    state.textBlockClosed = true;
                }

                // 关闭 reasoning 块（如果还没关闭）
                if (state.reasoningStarted && !state.reasoningEnded) {
                    state.reasoningEnded = true;
                    events.push({
                        type: 'content_block_stop',
                        index: 0,
                    });
                }

                // 确定工具调用的索引
                // 索引计算：reasoning块(0) + 文本块(如果有) + 之前的工具块
                let toolIndex = 0;
                if (state.reasoningStarted) {
                    toolIndex = 1; // reasoning 块占用索引 0
                }
                if (state.responseStarted) {
                    toolIndex = state.currentBlockIndex + 1; // 文本块之后
                }
                // 如果已经有工具调用，使用 toolUseIndex
                if (state.toolUseIndex > 1) {
                    toolIndex = state.toolUseIndex;
                }

                state.currentToolIndex = toolIndex;
                state.currentToolId = toolCallId;
                state.currentToolName = mappedToolName;
                state.currentToolInput = '';
                state.currentToolHadDelta = false;
                state.toolUseIndex = toolIndex + 1;

                // 记录到 pendingTools
                state.pendingTools[toolCallId] = {
                    id: toolCallId,
                    name: mappedToolName,
                    input: {},
                };

                console.log(`[Orchids] Tool call started: ${mappedToolName} (${toolCallId}) at index ${toolIndex}`);

                events.push({
                    type: 'content_block_start',
                    index: toolIndex,
                    content_block: {
                        type: 'tool_use',
                        id: toolCallId,
                        name: mappedToolName,
                        input: {},
                    },
                });

                return events.length > 0 ? events : null;
            }
            
            if (eventType === 'tool-input-delta') {
                if (!emitToolUse) return null;
                const delta = event.delta || '';
                if (delta && state.currentToolId) {
                    state.currentToolInput += delta;
                    state.currentToolHadDelta = true;
                    
                    events.push({
                        type: 'content_block_delta',
                        index: state.currentToolIndex,
                        delta: {
                            type: 'input_json_delta',
                            partial_json: delta,
                        },
                    });
                }
                return events.length > 0 ? events : null;
            }
            
            if (eventType === 'tool-input-end') {
                if (!emitToolUse) return null;
                // 工具输入结束，解析完整的 JSON 参数
                if (state.currentToolId && state.currentToolInput) {
                    try {
                        const parsedInput = JSON.parse(state.currentToolInput);
                        if (state.pendingTools[state.currentToolId]) {
                            state.pendingTools[state.currentToolId].input = parsedInput;
                        }
                    } catch (e) {
                        console.warn(`[Orchids] Failed to parse tool input: ${e.message}`);
                    }
                }
                
                if (state.currentToolId && state.currentToolIndex !== undefined) {
                    if (!state.currentToolHadDelta && state.currentToolInput) {
                        events.push({
                            type: 'content_block_delta',
                            index: state.currentToolIndex,
                            delta: {
                                type: 'input_json_delta',
                                partial_json: state.currentToolInput,
                            },
                        });
                    }
                    
                    events.push({
                        type: 'content_block_stop',
                        index: state.currentToolIndex,
                    });
                    
                    state.currentToolId = null;
                    state.currentToolName = null;
                    state.currentToolInput = '';
                    state.currentToolIndex = undefined;
                    state.currentToolHadDelta = false;
                }
                
                return events.length > 0 ? events : null;
            }
            
            if (eventType === 'tool-call') {
                if (!emitToolUse) return null;
                // 完整的工具调用信息，可以用来验证/补充
                // 注意：tool-call 事件可能在 tool-input-end 之前到达，且 toolCallId 可能与 tool-input-start 的 id 不同
                // 这种情况下，我们应该忽略这个事件，让 tool-input-end 来处理
                const toolCallId = event.toolCallId || state.currentToolId;
                const inputStr = event.input || '';

                // 如果当前有正在进行的工具调用，且 toolCallId 不匹配，忽略这个事件
                if (state.currentToolId && toolCallId !== state.currentToolId) {
                    console.log(`[Orchids] Ignoring tool-call with mismatched id: ${toolCallId} vs ${state.currentToolId}`);
                    return null;
                }

                // 如果 toolCallId 匹配，更新 pendingTools 的 input
                if (toolCallId && state.pendingTools[toolCallId]) {
                    try {
                        const parsedInput = JSON.parse(inputStr);
                        state.pendingTools[toolCallId].input = parsedInput;
                    } catch (e) {
                        // 忽略解析错误
                    }
                }

                // 只有在没有正在进行的工具调用时才关闭工具调用块
                // 因为 tool-input-end 会处理关闭
                // 这里不再重置状态，让 tool-input-end 来处理

                return events.length > 0 ? events : null;
            }
            
            // --------------------------------------------------------------------
            // 处理 text 事件（文本输出）
            // --------------------------------------------------------------------
            if (eventType === 'text-start') {
                if (!state.responseStarted) {
                    state.responseStarted = true;
                    state.currentBlockIndex = state.reasoningStarted ? 1 : 0;
                    state.textBlockClosed = false;
                    events.push({
                        type: 'content_block_start',
                        index: state.currentBlockIndex,
                        content_block: {
                            type: 'text',
                            text: '',
                        },
                    });
                }
                return events.length > 0 ? events : null;
            }

            if (eventType === 'text-delta') {
                const text = event.delta || '';
                if (text) {
                    // 累积文本用于后续解析工具调用
                    state.accumulatedText += text;

                    if (!state.responseStarted) {
                        state.responseStarted = true;
                        state.currentBlockIndex = state.reasoningStarted ? 1 : 0;
                        state.textBlockClosed = false;
                        events.push({
                            type: 'content_block_start',
                            index: state.currentBlockIndex,
                            content_block: {
                                type: 'text',
                                text: '',
                            },
                        });
                    }

                    // 发送文本增量事件
                    events.push({
                        type: 'content_block_delta',
                        index: state.currentBlockIndex,
                        delta: {
                            type: 'text_delta',
                            text: text,
                        },
                    });
                }
                return events.length > 0 ? events : null;
            }
            
            if (eventType === 'text-end') {
                // 文本块结束，但不立即关闭，等待可能的工具调用
                return null;
            }
            
            // --------------------------------------------------------------------
            // 处理 finish 事件（模型完成）
            // --------------------------------------------------------------------
            if (eventType === 'finish') {
                const finishReason = event.finishReason || 'stop';
                const usage = event.usage || {};
                
                // 更新 usage 信息
                if (usage.inputTokens !== undefined) {
                    state.usage.input_tokens = usage.inputTokens;
                }
                if (usage.outputTokens !== undefined) {
                    state.usage.output_tokens = usage.outputTokens;
                }
                if (usage.cachedInputTokens !== undefined) {
                    state.usage.cache_read_input_tokens = usage.cachedInputTokens;
                }
                
                // 设置 finish reason
                if (finishReason === 'tool-calls') {
                    state.finishReason = 'tool_use';
                } else if (finishReason === 'stop') {
                    state.finishReason = 'end_turn';
                } else {
                    state.finishReason = finishReason;
                }
                
                console.log(`[Orchids] Model finish: reason=${finishReason}, usage=${JSON.stringify(usage)}`);
                return null;
            }
            
            // --------------------------------------------------------------------
            // 处理 stream-start 事件
            // --------------------------------------------------------------------
            if (eventType === 'stream-start') {
                // 流开始，不需要特殊处理
                return null;
            }
            
            return null;
        }
        
        // ========================================================================
        // 处理 coding_agent.Edit 事件（文件编辑工具调用）
        // ========================================================================
        if (msgType === 'coding_agent.Edit.edit.started') {
            if (!emitToolUse) return null;
            const filePath = orchidsMessage.data?.file_path || '';
            const toolCallId = `toolu_edit_${uuidv4().replace(/-/g, '').substring(0, 8)}`;
            
            // 关闭之前的文本块（如果有）
            if (state.responseStarted && !state.textBlockClosed) {
                events.push({
                    type: 'content_block_stop',
                    index: state.currentBlockIndex,
                });
                state.textBlockClosed = true;
            }
            
            // 确定工具调用的索引
            let toolIndex = 0;
            if (state.reasoningStarted) {
                toolIndex = 1;
            }
            if (state.responseStarted) {
                toolIndex = state.currentBlockIndex + 1;
            }
            if (state.toolUseIndex > 1) {
                toolIndex = state.toolUseIndex;
            }
            
            state.currentEditToolIndex = toolIndex;
            state.currentEditToolId = toolCallId;
            state.currentEditFilePath = filePath;
            state.currentEditOldString = '';
            state.currentEditNewString = '';
            state.toolUseIndex = toolIndex + 1;
            
            console.log(`[Orchids] Edit started: ${filePath} (${toolCallId})`);
            
            // 记录到 pendingTools
            state.pendingTools[toolCallId] = {
                id: toolCallId,
                name: 'Edit',
                input: { file_path: filePath },
            };
            
            events.push({
                type: 'content_block_start',
                index: toolIndex,
                content_block: {
                    type: 'tool_use',
                    id: toolCallId,
                    name: 'Edit',
                    input: { file_path: filePath },
                },
            });
            
            return events.length > 0 ? events : null;
        }
        
        if (msgType === 'coding_agent.Edit.edit.chunk') {
            // 编辑内容的增量更新
            const text = orchidsMessage.data?.text || '';
            if (text && state.currentEditToolId) {
                state.currentEditNewString += text;
            }
            return null;
        }
        
        if (msgType === 'coding_agent.Edit.edit.completed') {
            // 编辑完成，但不关闭工具调用块，等待 edit_file.completed
            return null;
        }
        
        if (msgType === 'coding_agent.edit_file.started') {
            if (!emitToolUse) return null;
            // 文件编辑开始，可能是新的编辑或继续之前的编辑
            const filePath = orchidsMessage.data?.file_path || '';
            if (!state.currentEditToolId) {
                // 如果没有当前编辑工具，创建一个新的
                const toolCallId = `toolu_edit_${uuidv4().replace(/-/g, '').substring(0, 8)}`;
                
                // 关闭之前的文本块（如果有）
                if (state.responseStarted && !state.textBlockClosed) {
                    events.push({
                        type: 'content_block_stop',
                        index: state.currentBlockIndex,
                    });
                    state.textBlockClosed = true;
                }
                
                // 确定工具调用的索引
                let toolIndex = 0;
                if (state.reasoningStarted) {
                    toolIndex = 1;
                }
                if (state.responseStarted) {
                    toolIndex = state.currentBlockIndex + 1;
                }
                if (state.toolUseIndex > 1) {
                    toolIndex = state.toolUseIndex;
                }
                
                state.currentEditToolIndex = toolIndex;
                state.currentEditToolId = toolCallId;
                state.currentEditFilePath = filePath;
                state.toolUseIndex = toolIndex + 1;
                
                state.pendingTools[toolCallId] = {
                    id: toolCallId,
                    name: 'Edit',
                    input: { file_path: filePath },
                };
                
                events.push({
                    type: 'content_block_start',
                    index: toolIndex,
                    content_block: {
                        type: 'tool_use',
                        id: toolCallId,
                        name: 'Edit',
                        input: { file_path: filePath },
                    },
                });
            }
            return events.length > 0 ? events : null;
        }
        
        if (msgType === 'coding_agent.edit_file.chunk') {
            // 文件内容块，通常包含完整的新文件内容
            return null;
        }
        
        if (msgType === 'coding_agent.edit_file.completed') {
            if (!emitToolUse) return null;
            const data = orchidsMessage.data || {};
            const filePath = data.file_path || state.currentEditFilePath || '';
            const oldCode = data.old_code || '';
            const newCode = data.new_code || '';
            const oldString = data.old_string || state.currentEditOldString || '';
            const newString = data.new_string || state.currentEditNewString || '';
            
            if (state.currentEditToolId) {
                // 更新工具输入参数
                const toolInput = {
                    file_path: filePath,
                    old_string: oldString || oldCode?.substring(0, 100) || '',
                    new_string: newString || newCode?.substring(0, 100) || '',
                };
                
                if (state.pendingTools[state.currentEditToolId]) {
                    state.pendingTools[state.currentEditToolId].input = toolInput;
                }
                
                // 发送工具参数增量
                events.push({
                    type: 'content_block_delta',
                    index: state.currentEditToolIndex,
                    delta: {
                        type: 'input_json_delta',
                        partial_json: JSON.stringify(toolInput),
                    },
                });
                
                // 关闭工具调用块
                events.push({
                    type: 'content_block_stop',
                    index: state.currentEditToolIndex,
                });
                
                console.log(`[Orchids] Edit completed: ${filePath}`);
                
                // 重置编辑状态
                state.currentEditToolId = null;
                state.currentEditToolIndex = undefined;
                state.currentEditFilePath = '';
                state.currentEditOldString = '';
                state.currentEditNewString = '';
            }
            
            return events.length > 0 ? events : null;
        }
        
        // ========================================================================
        // 处理 coding_agent.todo_write 事件（待办列表工具调用）
        // ========================================================================
        if (msgType === 'coding_agent.todo_write.started') {
            if (!emitToolUse) return null;
            const todos = orchidsMessage.data?.todos || [];
            const toolCallId = `toolu_todo_${uuidv4().replace(/-/g, '').substring(0, 8)}`;
            
            // 关闭之前的文本块（如果有）
            if (state.responseStarted && !state.textBlockClosed) {
                events.push({
                    type: 'content_block_stop',
                    index: state.currentBlockIndex,
                });
                state.textBlockClosed = true;
            }
            
            // 确定工具调用的索引
            let toolIndex = 0;
            if (state.reasoningStarted) {
                toolIndex = 1;
            }
            if (state.responseStarted) {
                toolIndex = state.currentBlockIndex + 1;
            }
            if (state.toolUseIndex > 1) {
                toolIndex = state.toolUseIndex;
            }
            state.toolUseIndex = toolIndex + 1;
            
            state.pendingTools[toolCallId] = {
                id: toolCallId,
                name: 'TodoWrite',
                input: { todos },
            };
            
            events.push({
                type: 'content_block_start',
                index: toolIndex,
                content_block: {
                    type: 'tool_use',
                    id: toolCallId,
                    name: 'TodoWrite',
                    input: { todos },
                },
            });
            
            events.push({
                type: 'content_block_delta',
                index: toolIndex,
                delta: {
                    type: 'input_json_delta',
                    partial_json: JSON.stringify({ todos }),
                },
            });
            
            events.push({
                type: 'content_block_stop',
                index: toolIndex,
            });
            
            return events.length > 0 ? events : null;
        }
        
        if (msgType === 'coding_agent.todo_write.completed') {
            // 待办列表写入完成，不需要额外处理
            return null;
        }
        
        if (msgType === 'coding_agent.response.chunk') {
            state.preferCodingAgentEvents = true;
            const chunk = orchidsMessage.chunk;
            const text = typeof chunk === 'string' ? chunk : (chunk?.content || chunk?.text || '');
            if (!text) return null;
            
            if (!state.responseStarted) {
                state.responseStarted = true;
                state.currentBlockIndex = state.reasoningStarted ? 1 : 0;
                state.textBlockClosed = false;
                events.push({
                    type: 'content_block_start',
                    index: state.currentBlockIndex,
                    content_block: {
                        type: 'text',
                        text: '',
                    },
                });
            }
            
            if (text === state.lastTextDelta) return events.length > 0 ? events : null;
            state.lastTextDelta = text;
            
            events.push({
                type: 'content_block_delta',
                index: state.currentBlockIndex,
                delta: {
                    type: 'text_delta',
                    text: text,
                },
            });
            
            return events.length > 0 ? events : null;
        }
        
        if (msgType === 'output_text_delta') {
            state.preferCodingAgentEvents = true;
            const text = orchidsMessage.textDelta || orchidsMessage.delta || orchidsMessage.text || '';
            if (!text) return null;
            
            if (!state.responseStarted) {
                state.responseStarted = true;
                state.currentBlockIndex = state.reasoningStarted ? 1 : 0;
                state.textBlockClosed = false;
                events.push({
                    type: 'content_block_start',
                    index: state.currentBlockIndex,
                    content_block: {
                        type: 'text',
                        text: '',
                    },
                });
            }
            
            if (text === state.lastTextDelta) return events.length > 0 ? events : null;
            state.lastTextDelta = text;
            
            events.push({
                type: 'content_block_delta',
                index: state.currentBlockIndex,
                delta: {
                    type: 'text_delta',
                    text: text,
                },
            });
            return events.length > 0 ? events : null;
        }
        
        // ========================================================================
        // 处理 run_item_stream_event 事件（工具调用项）
        // ========================================================================
        if (msgType === 'run_item_stream_event') {
            const item = orchidsMessage.item || {};
            if (item.type === 'tool_call_item') {
                const rawItem = item.rawItem || {};
                if (rawItem.type === 'function_call' && rawItem.status === 'completed') {
                    // 这是一个已完成的工具调用，通常在 response_done 之后
                    // 不需要额外处理，因为我们已经在 response_done 中处理了
                    console.log(`[Orchids] Tool call item: ${rawItem.name} (${rawItem.callId})`);
                }
            }
            return null;
        }
        
        // ========================================================================
        // 处理 tool_call_output_item 事件（工具调用结果）
        // ========================================================================
        if (msgType === 'tool_call_output_item') {
            const rawItem = orchidsMessage.rawItem || {};
            if (rawItem.type === 'function_call_result') {
                const toolName = rawItem.name || 'unknown';
                const callId = rawItem.callId || '';
                const output = rawItem.output?.text || orchidsMessage.output || '';
                console.log(`[Orchids] Tool result: ${toolName} (${callId}) -> ${output.substring(0, 100)}...`);
            }
            return null;
        }
        
        return null;
    }

    _convertFsOperationToToolUse(fsOp, blockIndex) {
        const opId = fsOp.id;
        const opType = fsOp.operation || '';
        
        const toolMapping = {
            'list': 'LS',
            'read': 'Read',
            'write': 'Create',
            'edit': 'Edit',
            'grep': 'Grep',
            'glob': 'Glob',
            'run_command': 'Execute',
            'ripgrep': 'Grep',
        };
        
        const toolName = toolMapping[opType] || opType;
        
        let toolInput = {};
        
        if (opType === 'list') {
            toolInput = { path: fsOp.path || '.' };
        } else if (opType === 'read') {
            toolInput = { file_path: fsOp.path || '' };
        } else if (opType === 'write') {
            if (fsOp.old_content !== undefined) {
                toolInput = {
                    file_path: fsOp.path || '',
                    old_str: fsOp.old_content || '',
                    new_str: fsOp.new_content || fsOp.content || '',
                };
            } else {
                toolInput = {
                    file_path: fsOp.path || '',
                    content: fsOp.content || '',
                };
            }
        } else if (opType === 'run_command') {
            toolInput = { command: fsOp.command || '' };
        } else if (opType === 'grep' || opType === 'ripgrep') {
            toolInput = {
                pattern: fsOp.pattern || '',
                path: fsOp.path || '.',
            };
        } else if (opType === 'glob') {
            toolInput = {
                pattern: fsOp.pattern || '*',
                path: fsOp.path || '.',
            };
        }
        
        return [
            {
                type: 'content_block_start',
                index: blockIndex,
                content_block: {
                    type: 'tool_use',
                    id: opId,
                    name: toolName,
                    input: toolInput,
                },
            },
            {
                type: 'content_block_delta',
                index: blockIndex,
                delta: {
                    type: 'input_json_delta',
                    partial_json: JSON.stringify(toolInput),
                },
            },
        ];
    }

    /**
     * 流式生成内容 - 核心方法（高可用模式：每次请求新建连接）
     * 参考 simple_api.py 的实现方式，每次请求新建 WebSocket 连接，请求完成后立即关闭
     */
    async *generateContentStream(model, requestBody) {
        if (!this.isInitialized) await this.initialize();

        // 模型映射：将不支持的模型名称转换为支持的模型
        const MODEL_MAPPING = {
            'claude-haiku-4-5': 'claude-sonnet-4-5',
            'claude-opus-4-5': 'claude-opus-4.5',
        };
        const mappedModel = MODEL_MAPPING[model] || model;
        const finalModel = ORCHIDS_MODELS.includes(mappedModel) ? mappedModel : ORCHIDS_CONSTANTS.DEFAULT_MODEL;
        const requestId = uuidv4();
        const messageId = `msg_${requestId}`;
        // 默认启用工具调用输出，与 Kiro 行为一致
        const emitToolUse = this.config?.ORCHIDS_EMIT_TOOL_USE !== false;
        const clientToolIndex = this._buildClientToolIndex(requestBody?.tools);
        
        // 状态跟踪
        const state = {
            reasoningStarted: false,
            reasoningEnded: false,
            responseStarted: false,
            textBlockClosed: false,
            currentBlockIndex: -1,
            toolUseIndex: 1,
            pendingTools: {},
            inEditMode: false,
            responseDoneReceived: false,
            accumulatedText: '', // 累积文本用于解析 XML 工具调用
            preferCodingAgentEvents: false,
            lastTextDelta: '',
            // 当前工具调用状态（model.tool-input-* 事件）
            currentToolId: null,
            currentToolName: null,
            currentToolInput: '',
            currentToolIndex: undefined,
            currentToolHadDelta: false,
            // 当前编辑工具状态（coding_agent.Edit.* 事件）
            currentEditToolId: null,
            currentEditToolIndex: undefined,
            currentEditFilePath: '',
            currentEditOldString: '',
            currentEditNewString: '',
            // finish 信息
            finishReason: null,
            usage: {
                input_tokens: 0,
                output_tokens: 0,
                cache_read_input_tokens: 0,
            },
            clientToolIndex,
        };
        
        // 消息队列和控制
        const messageQueue = [];
        let resolveMessage = null;
        let isComplete = false;
        let ws = null;
        
        const waitForMessage = () => {
            return new Promise((resolve) => {
                if (messageQueue.length > 0) {
                    resolve(messageQueue.shift());
                } else {
                    resolveMessage = resolve;
                }
            });
        };
        
        // 关闭 WebSocket 连接的辅助函数
        const closeWebSocket = () => {
            if (ws) {
                try {
                    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
                        ws.close(1000, 'Request completed');
                    }
                } catch (error) {
                    console.warn(`[Orchids] Error closing WebSocket: ${error.message}`);
                }
                ws = null;
            }
        };
        
        const maxRetries = Number.isFinite(this.config?.ORCHIDS_WS_MAX_RETRIES) ? this.config.ORCHIDS_WS_MAX_RETRIES : 1;
        let yieldedOutput = false;

        // 日志持久化：记录完整的 WebSocket 消息流
        const logEnabled = this.config?.ORCHIDS_LOG_ENABLED !== false;
        const logDir = this.config?.ORCHIDS_LOG_DIR || 'configs/orchidslog';
        const logTimestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const logFileName = `orchids_${logTimestamp}_${requestId.substring(0, 8)}.log`;
        const logFilePath = path.join(logDir, logFileName);
        const logEntries = [];

        const appendLog = (direction, type, data) => {
            if (!logEnabled) return;
            const entry = {
                timestamp: new Date().toISOString(),
                direction, // 'SEND' | 'RECV' | 'INFO' | 'ERROR'
                type,
                data,
            };
            logEntries.push(entry);
        };

        const flushLog = async () => {
            if (!logEnabled || logEntries.length === 0) return;
            try {
                await fs.mkdir(logDir, { recursive: true });
                const logContent = logEntries.map(e => JSON.stringify(e)).join('\n');
                await fs.writeFile(logFilePath, logContent, 'utf8');
                console.log(`[Orchids] Log saved to ${logFilePath}`);
            } catch (e) {
                console.warn(`[Orchids] Failed to save log: ${e.message}`);
            }
        };

        appendLog('INFO', 'request_start', { model, finalModel, messageId, emitToolUse });

        yield {
            type: 'message_start',
            message: {
                id: messageId,
                type: 'message',
                role: 'assistant',
                model: model,
                usage: { input_tokens: 0, output_tokens: 0 },
                content: [],
            },
        };
        
        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            let completedByProtocol = false;
            let lastClose = null;
            isComplete = false;
            messageQueue.length = 0;
            resolveMessage = null;
            
            try {
                await this.ensureValidToken();
                
                const wsEndpoint = this.config?.ORCHIDS_ENDPOINT || ORCHIDS_CONSTANTS.DEFAULT_ENDPOINT;
                const wsUrl = this._buildAgentWsUrl(wsEndpoint);
                
                ws = new WebSocket(wsUrl, {
                    headers: {
                        'User-Agent': ORCHIDS_CONSTANTS.USER_AGENT,
                        'Origin': ORCHIDS_CONSTANTS.ORIGIN,
                    },
                });
                
                await new Promise((resolve, reject) => {
                    let resolved = false;
                    const connectionTimeout = setTimeout(() => {
                        reject(new Error('[Orchids WS] Connection timeout'));
                    }, 30000);
                    
                    ws.on('open', () => {
                        if (resolved) return;
                        resolved = true;
                        clearTimeout(connectionTimeout);
                        resolve();
                    });
                    
                    ws.on('message', (data) => {
                        try {
                            const message = JSON.parse(data.toString());
                            if (message.type === 'connected') {
                                if (!resolved) {
                                    resolved = true;
                                    clearTimeout(connectionTimeout);
                                    resolve();
                                }
                                return;
                            }
                            
                            if (resolveMessage) {
                                const resolver = resolveMessage;
                                resolveMessage = null;
                                resolver(message);
                            } else {
                                messageQueue.push(message);
                            }
                        } catch (e) {
                            // ignore
                        }
                    });
                    
                    ws.on('error', (error) => {
                        clearTimeout(connectionTimeout);
                        reject(error);
                    });
                    
                    ws.on('close', (code, reason) => {
                        lastClose = { code, reason: reason?.toString?.() || '' };
                        isComplete = true;
                        if (resolveMessage) {
                            resolveMessage(null);
                        }
                    });
                });
                
                const orchidsRequest = await this._convertToOrchidsRequest(finalModel, requestBody, requestBody.thinking, requestBody.tools);
                appendLog('SEND', 'user_request', orchidsRequest);
                ws.send(JSON.stringify(orchidsRequest));

                while (!isComplete) {
                    const message = await Promise.race([
                        waitForMessage(),
                        new Promise((resolve) => setTimeout(() => resolve('timeout'), 120000)),
                    ]);

                    if (message === 'timeout') {
                        appendLog('ERROR', 'timeout', { reason: 'Message timeout after 120s' });
                        throw new Error('[Orchids WS] Message timeout');
                    }

                    if (!message) {
                        appendLog('INFO', 'ws_closed', { reason: 'No more messages' });
                        break;
                    }

                    // 记录收到的每条消息
                    appendLog('RECV', message.type || 'unknown', message);

                    const msgType = message.type;
                    
                    if (msgType === 'coding_agent.tokens_used') {
                        const data = message.data || {};
                        if (data.input_tokens !== undefined) {
                            state.usage.input_tokens = data.input_tokens;
                        }
                        if (data.output_tokens !== undefined) {
                            state.usage.output_tokens = data.output_tokens;
                        }
                        console.log(`[Orchids] Tokens used: input=${state.usage.input_tokens}, output=${state.usage.output_tokens}`);
                        continue;
                    }
                    
                    if (msgType === 'coding_agent.Edit.started') {
                        state.inEditMode = true;
                    }
                    if (msgType === 'coding_agent.edit_file.completed') {
                        state.inEditMode = false;
                    }
                    
                    if (msgType === 'fs_operation') {
                        const opId = message.id;
                        const opType = message.operation || '';
                        
                        console.log(`[Orchids FS] Received: ${opType}: ${message.path || message.command || ''}`);
                        await this._handleFsOperation(ws, message, this.config?.ORCHIDS_LOCAL_WORKDIR);
                        console.log(`[Orchids FS] Responded: ${opId}`);
                        continue;
                    }
                    
                    const sseEvent = this._convertToAnthropicSSE(message, state);
                    if (sseEvent) {
                        if (Array.isArray(sseEvent)) {
                            for (const event of sseEvent) {
                                yieldedOutput = true;
                                yield event;
                            }
                        } else {
                            yieldedOutput = true;
                            yield sseEvent;
                        }
                    }
                    
                    if (msgType === 'response_done' || msgType === 'coding_agent.end' || msgType === 'complete') {
                        completedByProtocol = true;
                        if (msgType === 'response_done') {
                            const responseUsage = message.response?.usage;
                            if (responseUsage) {
                                if (responseUsage.inputTokens !== undefined) {
                                    state.usage.input_tokens = responseUsage.inputTokens;
                                }
                                if (responseUsage.outputTokens !== undefined) {
                                    state.usage.output_tokens = responseUsage.outputTokens;
                                }
                                if (responseUsage.cachedInputTokens !== undefined) {
                                    state.usage.cache_read_input_tokens = responseUsage.cachedInputTokens;
                                }
                                console.log(`[Orchids] Response usage: input=${state.usage.input_tokens}, output=${state.usage.output_tokens}, cached=${state.usage.cache_read_input_tokens}`);
                            }
                            
                            const outputs = message.response?.output || [];
                            for (const output of outputs) {
                                // function_call 可能没有 status 字段，或者 status 为 'completed'
                                if (output.type === 'function_call') {
                                    const toolCallId = output.callId || `toolu_${uuidv4().replace(/-/g, '').substring(0, 12)}`;
                                    const toolName = output.name || 'unknown';
                                    let toolInput = {};
                                    
                                    try {
                                        toolInput = JSON.parse(output.arguments || '{}');
                                    } catch (e) {
                                        console.warn(`[Orchids] Failed to parse function_call arguments: ${e.message}`);
                                    }

                                    const mappedToolName = this._mapToolNameToClient(toolName, toolInput, state.clientToolIndex);
                                    
                                    if (emitToolUse && !state.pendingTools[toolCallId]) {
                                        if (state.responseStarted && !state.textBlockClosed) {
                                            yieldedOutput = true;
                                            yield {
                                                type: 'content_block_stop',
                                                index: state.currentBlockIndex,
                                            };
                                            state.textBlockClosed = true;
                                        }
                                        
                                        let toolIndex = 0;
                                        if (state.reasoningStarted) {
                                            toolIndex = 1;
                                        }
                                        if (state.responseStarted) {
                                            toolIndex = state.currentBlockIndex + 1;
                                        }
                                        if (state.toolUseIndex > 1) {
                                            toolIndex = state.toolUseIndex;
                                        }
                                        state.toolUseIndex = toolIndex + 1;
                                        
                                        state.pendingTools[toolCallId] = {
                                            id: toolCallId,
                                            name: mappedToolName,
                                            input: toolInput,
                                        };
                                        
                                        yieldedOutput = true;
                                        yield {
                                            type: 'content_block_start',
                                            index: toolIndex,
                                            content_block: {
                                                type: 'tool_use',
                                                id: toolCallId,
                                                name: mappedToolName,
                                                input: toolInput,
                                            },
                                        };
                                        
                                        yield {
                                            type: 'content_block_delta',
                                            index: toolIndex,
                                            delta: {
                                                type: 'input_json_delta',
                                                partial_json: JSON.stringify(toolInput),
                                            },
                                        };
                                        
                                        yield { type: 'content_block_stop', index: toolIndex };
                                    }
                                }
                            }
                        }
                        
                        if (state.responseStarted && !state.textBlockClosed) {
                            yieldedOutput = true;
                            yield {
                                type: 'content_block_stop',
                                index: state.currentBlockIndex,
                            };
                            state.textBlockClosed = true;
                        }
                        
                        const hasToolUse = Object.keys(state.pendingTools).length > 0;
                        const stopReason = state.finishReason || ((emitToolUse && hasToolUse) ? 'tool_use' : 'end_turn');
                        
                        yield {
                            type: 'message_delta',
                            delta: {
                                stop_reason: stopReason,
                                stop_sequence: null,
                            },
                            usage: { ...state.usage },
                        };
                        
                        yield { type: 'message_stop' };
                        appendLog('INFO', 'request_complete', {
                            stopReason,
                            usage: state.usage,
                            pendingToolsCount: Object.keys(state.pendingTools).length,
                            yieldedOutput,
                        });
                        await flushLog();
                        break;
                    }
                }

                if (completedByProtocol) return;
                const closeHint = lastClose ? `code=${lastClose.code} reason=${lastClose.reason}` : 'no-close-info';
                appendLog('ERROR', 'incomplete', { closeHint });
                await flushLog();
                throw new Error(`[Orchids WS] Connection closed before completion (${closeHint})`);
            } catch (error) {
                appendLog('ERROR', 'exception', { message: error.message, stack: error.stack });
                await flushLog();
                closeWebSocket();
                if (attempt < maxRetries && !yieldedOutput) {
                    try {
                        await this.initializeAuth(true);
                    } catch {
                        // ignore
                    }
                    continue;
                }
                throw error;
            } finally {
                closeWebSocket();
            }
        }
    }

    async generateContent(model, requestBody) {
        if (!this.isInitialized) await this.initialize();
        
        const events = [];
        const emitToolUse = this.config?.ORCHIDS_EMIT_TOOL_USE === true;
        let thinking = '';
        let text = '';
        const toolCallsById = new Map();
        const toolInputBuffersByIndex = new Map();
        const toolIdByIndex = new Map();
        const toolCallOrder = [];
        
        for await (const event of this.generateContentStream(model, requestBody)) {
            events.push(event);
            
            if (emitToolUse && event.type === 'content_block_start' && event.content_block?.type === 'tool_use') {
                const id = event.content_block.id;
                toolCallsById.set(id, {
                    type: 'tool_use',
                    id,
                    name: event.content_block.name,
                    input: {},
                });
                toolInputBuffersByIndex.set(event.index, '');
                toolIdByIndex.set(event.index, id);
                toolCallOrder.push(id);
            }
            
            if (event.type === 'content_block_delta') {
                if (event.delta?.type === 'text_delta') {
                    text += event.delta.text || '';
                }
                if (event.delta?.type === 'thinking_delta') {
                    thinking += event.delta.thinking || '';
                }
                if (emitToolUse && event.delta?.type === 'input_json_delta') {
                    const existing = toolInputBuffersByIndex.get(event.index) || '';
                    toolInputBuffersByIndex.set(event.index, existing + (event.delta.partial_json || ''));
                }
            }
            
            if (emitToolUse && event.type === 'content_block_stop') {
                const buffer = toolInputBuffersByIndex.get(event.index);
                if (buffer !== undefined) {
                    toolInputBuffersByIndex.delete(event.index);
                    const toolId = toolIdByIndex.get(event.index);
                    toolIdByIndex.delete(event.index);
                    try {
                        const parsed = JSON.parse(buffer || '{}');
                        if (toolId && toolCallsById.has(toolId)) {
                            toolCallsById.get(toolId).input = parsed;
                        }
                    } catch {
                        // ignore
                    }
                }
            }
        }
        
        const contentArray = [];
        if (thinking) {
            contentArray.push({ type: 'thinking', thinking });
        }
        if (text) {
            contentArray.push({ type: 'text', text });
        }
        if (emitToolUse) {
            for (const id of toolCallOrder) {
                const call = toolCallsById.get(id);
                if (call) contentArray.push(call);
            }
        }
        
        return {
            id: uuidv4(),
            type: 'message',
            role: 'assistant',
            model: model,
            stop_reason: emitToolUse && toolCallOrder.length > 0 ? 'tool_use' : 'end_turn',
            stop_sequence: null,
            usage: {
                input_tokens: 0,
                output_tokens: 100,
            },
            content: contentArray,
        };
    }

    async listModels() {
        const models = ORCHIDS_MODELS.map(id => ({ name: id }));
        return { models };
    }

    getContentText(content) {
        if (!content) return '';
        if (typeof content === 'string') return content;
        if (Array.isArray(content)) {
            return content
                .map((block) => {
                    if (!block) return '';
                    if (block.type === 'text') return block.text || '';
                    if (block.type === 'tool_result') return this.getContentText(block.content);
                    if (block.type === 'tool_use') return `${block.name || ''}\n${JSON.stringify(block.input || {})}`;
                    if (block.type === 'thinking') return block.thinking || '';
                    if (block.type === 'image') return '[image]';
                    if (block.type === 'document') return '[document]';
                    return '';
                })
                .filter(Boolean)
                .join('\n');
        }
        if (typeof content === 'object') {
            if (content.text) return String(content.text);
        }
        return '';
    }

    countTextTokens(text) {
        if (!text) return 0;
        try {
            return anthropicCountTokens(String(text));
        } catch {
            return Math.ceil(String(text).length / 4);
        }
    }

    estimateInputTokens(requestBody) {
        return this.countTokens(requestBody).input_tokens;
    }

    countTokens(requestBody) {
        let totalTokens = 0;

        if (requestBody?.system) {
            totalTokens += this.countTextTokens(this.getContentText(requestBody.system));
        }

        if (Array.isArray(requestBody?.messages)) {
            for (const message of requestBody.messages) {
                const content = message?.content;
                if (!content) continue;
                if (typeof content === 'string') {
                    totalTokens += this.countTextTokens(content);
                    continue;
                }
                if (!Array.isArray(content)) continue;
                for (const block of content) {
                    if (!block) continue;
                    if (block.type === 'text' && block.text) {
                        totalTokens += this.countTextTokens(block.text);
                    } else if (block.type === 'tool_use') {
                        totalTokens += this.countTextTokens(block.name || '');
                        totalTokens += this.countTextTokens(JSON.stringify(block.input || {}));
                    } else if (block.type === 'tool_result') {
                        totalTokens += this.countTextTokens(this.getContentText(block.content));
                    } else if (block.type === 'image') {
                        totalTokens += 1600;
                    } else if (block.type === 'document') {
                        if (block.source?.data) {
                            const estimatedChars = block.source.data.length * 0.75;
                            totalTokens += Math.ceil(estimatedChars / 4);
                        }
                    }
                }
            }
        }

        if (Array.isArray(requestBody?.tools)) {
            for (const tool of requestBody.tools) {
                totalTokens += this.countTextTokens(tool?.name || '');
                totalTokens += this.countTextTokens(tool?.description || '');
                if (tool?.input_schema) {
                    totalTokens += this.countTextTokens(JSON.stringify(tool.input_schema));
                }
            }
        }

        return { input_tokens: totalTokens };
    }

    async getUsageLimits() {
        if (!this.isInitialized) await this.initialize();
        return {
            supported: false,
            provider: 'claude-orchids-oauth',
            message: 'Orchids provider 暂无已知的稳定用量查询接口，返回占位结果。',
        };
    }

    isExpiryDateNear() {
        if (!this.tokenExpiresAt) return true;
        if (!this.clerkToken) return true;
        
        try {
            const expirationTime = new Date(this.tokenExpiresAt);
            const currentTime = new Date();
            const thresholdSeconds = this.config.CRON_NEAR_SECONDS || 30;
            const thresholdTime = new Date(currentTime.getTime() + thresholdSeconds * 1000);
            
            const isNear = expirationTime.getTime() <= thresholdTime.getTime();
            
            if (isNear) {
                const remainingSeconds = Math.max(0, Math.floor((expirationTime.getTime() - currentTime.getTime()) / 1000));
                console.log(`[Orchids Auth] Token expires in ${remainingSeconds}s, needs refresh`);
            }
            
            return isNear;
        } catch (error) {
            console.error(`[Orchids] Error checking expiry date: ${error.message}`);
            return true;
        }
    }

    async ensureValidToken() {
        // 参考 simple_api.py 的 refresh_token() 实现
        // 每次请求前检查是否需要重新获取 session 和 token
        // 因为 last_active_token 可能在使用后就失效，导致第二次请求 401 错误
        
        const TOKEN_REFRESH_BUFFER = 5 * 60 * 1000; // 5 分钟缓冲期
        const MIN_REFRESH_INTERVAL = 1000; // 最小刷新间隔 1 秒，防止重复刷新
        const now = Date.now();
        
        // 防止重复刷新（1秒内不重复刷新，避免 initialize() 后立即又刷新）
        if (now - this.lastTokenRefreshTime < MIN_REFRESH_INTERVAL) {
            return;
        }
        
        // 检查 Token 是否即将过期（5分钟内过期才刷新）
        if (this.tokenExpiresAt && (this.tokenExpiresAt - now) > TOKEN_REFRESH_BUFFER) {
            return;
        }
        
        console.log('[Orchids Auth] Refreshing token before request...');
        this.lastTokenRefreshTime = now;

        // 使用去重锁：多个并发刷新请求只执行一次，共享结果
        const dedupeKey = `orchids-token-refresh:${this.credPath}`;
        const credentialCache = CredentialCacheManager.getInstance();
        await credentialCache.withDeduplication(dedupeKey, async () => {
            await this.initializeAuth(true);
        });
        
        // 如果是等待其他请求完成的刷新，需要重新加载凭证
        // 因为 withDeduplication 会让所有等待者共享同一个 Promise
        // 但只有第一个调用者的实例会执行 initializeAuth 并更新自己的内存状态
        // 其他等待者需要从文件重新加载
        if (this.isExpiryDateNear()) {
            console.log('[Orchids Auth] Reloading credentials after concurrent refresh...');
            try {
                const fileContent = await fs.readFile(this.credPath, 'utf8');
                const credentials = JSON.parse(fileContent);
                
                if (credentials.expiresAt) {
                    this.tokenExpiresAt = new Date(credentials.expiresAt);
                }
                
                // 重新从 Clerk 获取 session 信息
                if (this.clientJwt || credentials.clientJwt || credentials.client_jwt) {
                    const clientJwt = this.clientJwt || credentials.clientJwt || credentials.client_jwt;
                    const sessionInfo = await this._getSessionFromClerk(clientJwt);
                    if (sessionInfo) {
                        this.clerkSessionId = sessionInfo.sessionId;
                        this.userId = sessionInfo.userId;
                        this.clerkToken = sessionInfo.wsToken;
                        
                        const jwtExpiry = this._parseJwtExpiry(this.clerkToken);
                        if (jwtExpiry) {
                            this.tokenExpiresAt = jwtExpiry;
                        }
                        console.log('[Orchids Auth] Credentials reloaded after concurrent refresh');
                    }
                }
            } catch (error) {
                console.warn(`[Orchids Auth] Failed to reload credentials after refresh: ${error.message}`);
            }
        }
        
        console.log('[Orchids Auth] Token refreshed successfully');
    }
}
