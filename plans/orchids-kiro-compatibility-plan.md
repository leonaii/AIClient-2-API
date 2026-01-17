# Orchids 与 Kiro 兼容性改进计划

## 上下文
文件名：orchids-kiro-compatibility-plan.md
创建于：2026-01-17T04:50:00+08:00
创建者：AI Architect
关联协议：RIPER-5 + Multidimensional + Agent Protocol

## 任务描述
根据逆向分析 Orchids Desktop 应用和对比 `claude-kiro.js` 实现，改进 `claude-orchids.js` 的 Claude 协议兼容性。

## 项目概述
AIClient-2-API 是一个 API 代理服务，支持多种 AI 提供商。`claude-orchids.js` 和 `claude-kiro.js` 都是 Claude API 的实现，但 Orchids 实现存在以下兼容性问题需要修复。

---

## 分析结果

### 1. Orchids API 请求格式（逆向分析）

从 `external/orchids-desktop/output_directory/renderer/assets/index-DmVTeEqF.js` 中发现的请求格式：

```javascript
// 行 96370-96390: sendRequest 调用
sendRequest({
    projectId,
    prompt: finalPrompt,
    agentMode,           // 模型选择，如 "claude-sonnet-4-5", "auto"
    mode: chatMode,      // "agent" 或 "chat"
    chatHistory,
    chatSessionId,
    attachmentUrls,
    filesInSession,
    currentPage,
    email,
    isLocal: true,
    localWorkingDirectory,
    isFixingErrors,
    detectedErrors,
    userId,
    fileStructure,
    templateId,
    isImportedProject
});
```

### 2. Thinking/Reasoning 事件处理（逆向分析）

从 `index-DmVTeEqF.js` 行 166402-166498 发现的事件类型：

```javascript
// Orchids 支持的 reasoning 事件
case "coding_agent.reasoning.started":
    callbacks.onThinkingStarted?.();
    break;
case "coding_agent.reasoning.chunk":
    if (event.data?.text) {
        callbacks.onThinkingChunk?.(event.data.text);
    }
    break;
case "coding_agent.reasoning.completed":
    callbacks.onThinkingCompleted?.(
        event.data?.text,
        event.data?.signature,
        event.data?.thinking_duration_ms
    );
    break;
```

### 3. 关键差异对比

| 功能 | Kiro 实现 | Orchids 实现 | 差异说明 |
|------|-----------|--------------|----------|
| **Thinking 参数** | 在 `buildCodewhispererRequest` 中通过 `_generateThinkingPrefix` 生成 `<thinking_mode>enabled</thinking_mode><max_thinking_length>N</max_thinking_length>` 前缀注入到 system prompt | 未传递 thinking 参数 | Orchids 需要添加 thinking 参数支持 |
| **工具定义传递** | 在 `userInputMessageContext.tools` 中传递完整的工具定义数组 | 不传递客户端定义的工具 | Orchids 需要添加工具定义传递 |
| **tool_result 处理** | 保留结构化的 `toolResults` 数组，包含 `toolUseId`, `content`, `status` | 将 tool_result 转为文本 `[Tool Result ${toolId}]\n${result}` | Orchids 需要保留结构化格式 |
| **错误处理** | 完整的凭证池管理、402/403/429 错误处理、配额检查 | 缺少凭证池管理和配额处理 | 可选改进 |
| **Token 刷新** | 支持后台异步刷新、去重锁 | 仅支持同步刷新 | 已实现基本功能 |

---

## 提议的解决方案

### 方案 A：最小改动方案（推荐）
仅修复核心兼容性问题，保持 Orchids 的简洁架构：
1. 添加 thinking 参数支持
2. 添加工具定义传递
3. 改进 tool_result 处理

### 方案 B：完整对齐方案
完全对齐 Kiro 的实现，包括：
1. 方案 A 的所有内容
2. 添加凭证池管理
3. 添加配额检查和 402 错误处理
4. 添加后台异步 token 刷新

**选择方案 A**，因为 Orchids 的架构与 Kiro 不同（WebSocket vs HTTP），完整对齐需要大量重构。

---

## 实施计划

### 修改文件
- `src/providers/claude/claude-orchids.js`

### 详细修改说明

#### 1. 添加 Thinking 参数支持

**位置**: 行 16-28 附近，添加常量定义

```javascript
// 新增 ORCHIDS_THINKING 常量
const ORCHIDS_THINKING = {
    MAX_BUDGET_TOKENS: 24576,
    DEFAULT_BUDGET_TOKENS: 20000,
    START_TAG: '<thinking>',
    END_TAG: '</thinking>',
    MODE_TAG: '<thinking_mode>',
    MAX_LEN_TAG: '<max_thinking_length>',
};
```

**位置**: 行 484-571 附近，修改 `_convertToOrchidsRequest` 方法

需要添加以下功能：
1. 接收 `thinking` 参数
2. 生成 thinking 前缀
3. 将前缀注入到 prompt 中

#### 2. 添加工具定义传递

**位置**: 行 484-571 附近，修改 `_convertToOrchidsRequest` 方法

需要添加以下功能：
1. 接收 `tools` 参数
2. 转换工具定义格式
3. 添加到请求数据中

#### 3. 改进 tool_result 处理

**位置**: 行 343-391 附近，修改 `_extractUserMessage` 方法
**位置**: 行 393-465 附近，修改 `_convertMessagesToChatHistory` 方法

需要修改以下功能：
1. 保留 tool_result 的结构化格式
2. 正确传递 tool_use_id

---

## 实施检查清单

### 阶段 1：添加 Thinking 支持

- [ ] 1.1 在文件顶部添加 `ORCHIDS_THINKING` 常量定义（行 28 后）
- [ ] 1.2 添加 `_normalizeThinkingBudgetTokens` 方法（参考 Kiro 行 796-803）
- [ ] 1.3 添加 `_generateThinkingPrefix` 方法（参考 Kiro 行 805-809）
- [ ] 1.4 添加 `_hasThinkingPrefix` 方法（参考 Kiro 行 811-814）
- [ ] 1.5 修改 `_convertToOrchidsRequest` 方法签名，添加 `thinking` 参数
- [ ] 1.6 在 `_convertToOrchidsRequest` 中生成 thinking 前缀并注入到 prompt
- [ ] 1.7 修改 `generateContentStream` 方法，传递 `requestBody.thinking` 到 `_convertToOrchidsRequest`

### 阶段 2：添加工具定义传递

- [ ] 2.1 修改 `_convertToOrchidsRequest` 方法签名，添加 `tools` 参数
- [ ] 2.2 添加工具定义转换逻辑（过滤 web_search，截断过长描述）
- [ ] 2.3 将转换后的工具定义添加到请求数据的 `data` 对象中
- [ ] 2.4 修改 `generateContentStream` 方法，传递 `requestBody.tools` 到 `_convertToOrchidsRequest`

### 阶段 3：改进 tool_result 处理

- [ ] 3.1 修改 `_extractUserMessage` 方法，保留 tool_result 结构
- [ ] 3.2 修改 `_convertMessagesToChatHistory` 方法，正确处理 tool_result
- [ ] 3.3 在请求数据中添加 `toolResults` 字段（如果有）

### 阶段 4：测试验证

- [ ] 4.1 测试普通对话（无 thinking，无 tools）
- [ ] 4.2 测试带 thinking 的对话
- [ ] 4.3 测试带工具定义的对话
- [ ] 4.4 测试工具调用和 tool_result 返回
- [ ] 4.5 验证流式输出格式正确

---

## 代码修改详情

### 1.1 添加 ORCHIDS_THINKING 常量

**文件**: `src/providers/claude/claude-orchids.js`
**位置**: 行 28 后（ORCHIDS_CONSTANTS 定义之后）

```javascript
const ORCHIDS_THINKING = {
    MAX_BUDGET_TOKENS: 24576,
    DEFAULT_BUDGET_TOKENS: 20000,
    START_TAG: '<thinking>',
    END_TAG: '</thinking>',
    MODE_TAG: '<thinking_mode>',
    MAX_LEN_TAG: '<max_thinking_length>',
};
```

### 1.2-1.4 添加 Thinking 辅助方法

**文件**: `src/providers/claude/claude-orchids.js`
**位置**: 行 319 后（`_updateCredentialsFile` 方法之后）

```javascript
_normalizeThinkingBudgetTokens(budgetTokens) {
    let value = Number(budgetTokens);
    if (!Number.isFinite(value) || value <= 0) {
        value = ORCHIDS_THINKING.DEFAULT_BUDGET_TOKENS;
    }
    value = Math.floor(value);
    return Math.min(value, ORCHIDS_THINKING.MAX_BUDGET_TOKENS);
}

_generateThinkingPrefix(thinking) {
    if (!thinking || thinking.type !== 'enabled') return null;
    const budget = this._normalizeThinkingBudgetTokens(thinking.budget_tokens);
    return `<thinking_mode>enabled</thinking_mode><max_thinking_length>${budget}</max_thinking_length>`;
}

_hasThinkingPrefix(text) {
    if (!text) return false;
    return text.includes(ORCHIDS_THINKING.MODE_TAG) || text.includes(ORCHIDS_THINKING.MAX_LEN_TAG);
}
```

### 1.5-1.6 修改 _convertToOrchidsRequest 方法

**文件**: `src/providers/claude/claude-orchids.js`
**位置**: 行 484-571

修改方法签名和实现：

```javascript
async _convertToOrchidsRequest(model, claudeRequest, tools = null, thinking = null) {
    const messages = claudeRequest.messages || [];
    
    // 提取 system prompt
    let systemPrompt = this._extractSystemPrompt(messages);
    const userMessage = this._extractUserMessage(messages);
    
    // 生成 thinking 前缀并注入到 system prompt
    const thinkingPrefix = this._generateThinkingPrefix(thinking);
    if (thinkingPrefix) {
        if (!systemPrompt) {
            systemPrompt = thinkingPrefix;
        } else if (!this._hasThinkingPrefix(systemPrompt)) {
            systemPrompt = `${thinkingPrefix}\n${systemPrompt}`;
        }
    }
    
    // ... 其余代码保持不变 ...
    
    // 构建请求数据
    const requestData = {
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
        },
    };
    
    // 添加工具定义（如果有）
    if (tools && Array.isArray(tools) && tools.length > 0) {
        const filteredTools = tools.filter(tool => {
            const name = (tool.name || '').toLowerCase();
            return name !== 'web_search' && name !== 'websearch';
        });
        
        if (filteredTools.length > 0) {
            const MAX_DESCRIPTION_LENGTH = 9216;
            requestData.data.tools = filteredTools.map(tool => {
                let desc = tool.description || "";
                if (desc.length > MAX_DESCRIPTION_LENGTH) {
                    desc = desc.substring(0, MAX_DESCRIPTION_LENGTH) + "...";
                }
                return {
                    name: tool.name,
                    description: desc,
                    input_schema: tool.input_schema || {}
                };
            });
        }
    }
    
    return requestData;
}
```

### 1.7 & 2.4 修改 generateContentStream 方法

**文件**: `src/providers/claude/claude-orchids.js`
**位置**: 行 1978 附近

```javascript
const orchidsRequest = await this._convertToOrchidsRequest(
    finalModel, 
    requestBody,
    requestBody.tools,      // 传递工具定义
    requestBody.thinking    // 传递 thinking 参数
);
```

### 3.1-3.2 改进 tool_result 处理

**文件**: `src/providers/claude/claude-orchids.js`
**位置**: 行 393-465（`_convertMessagesToChatHistory` 方法）

修改 tool_result 处理逻辑：

```javascript
_convertMessagesToChatHistory(messages) {
    const chatHistory = [];
    
    for (const msg of messages) {
        const role = msg.role;
        const content = msg.content;
        
        // ... 跳过 system reminder 的逻辑保持不变 ...
        
        if (role === 'user') {
            const textParts = [];
            const toolResults = [];
            
            if (typeof content === 'string') {
                textParts.push(content);
            } else if (Array.isArrt)) {
                for (const block of content) {
                    if (block.type === 'text') {
                        textParts.push(block.text || '');
                    } else if (block.type === 'tool_result') {
                        // 保留结构化的 tool_result
                        toolResults.push({
                            toolUseId: block.tool_use_id,
                            content: this.getContentText(block.content),
                            status: block.is_error ? 'error' : 'success'
                        });
                    } else if (block.type === 'image') {
                        // ... 保持不变 ...
                    }
                }
            }
            
            const historyEntry = { role: 'user', content: textParts.join('\n') };
            if (toolResults.length > 0) {
                historyEntry.toolResults = toolResults;
            }
            if (historyEntry.content || toolResults.length > 0) {
                chatHistory.push(historyEntry);
            }
        } else if (role === 'assistant') {
            // ... assistant 处理逻辑保持不变 ...
        }
    }
    
    return chatHistory;
}
```

---

## 风险评估

| 风险 | 可能性 | 影响 | 缓解措施 |
|------|--------|------|----------|
| Orchids API 不支持 thinking 前缀 | 低 | 中 | 逆向分析显示支持 reasoning 事件 |
| 工具定义格式不兼容 | 中 | 中 | 参考逆向分析的格式，添加错误处理 |
| tool_result 格式变更导致 API 错误 | 中 | 高 | 保留回退逻辑，支持文本格式 |
| 现有功能回归 | 低 | 高 | 分阶段实施，每阶段测试 |

---

## 最终审查检查点

- [ ] 所有代码修改符合项目编码规范
- [ ] 添加了适当的日志输出
- [ ] 错误处理完善
- [ ] 向后兼容（不破坏现有功能）
- [ ] 测试用例通过
