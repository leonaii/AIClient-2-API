import { countTokens as anthropicCountTokens } from '@anthropic-ai/tokenizer';
import { OrchidsApiService } from '../src/providers/claude/claude-orchids.js';

describe('OrchidsApiService kiro parity', () => {
    test('countTokens should follow kiro-compatible rules', () => {
        const service = new OrchidsApiService({});

        const requestBody = {
            system: 'sys',
            messages: [
                {
                    role: 'user',
                    content: [
                        { type: 'text', text: 'hi' },
                        { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AAAAAAAA' } },
                        { type: 'document', source: { type: 'base64', data: 'AAAAAAAA' } },
                    ],
                },
                {
                    role: 'assistant',
                    content: [
                        { type: 'tool_use', name: 'MyTool', input: { a: 1 } },
                        { type: 'tool_result', tool_use_id: 'toolu_1', content: 'ok' },
                    ],
                },
            ],
            tools: [{ name: 't', description: 'd', input_schema: { type: 'object' } }],
        };

        const result = service.countTokens(requestBody);

        const expected =
            anthropicCountTokens('sys') +
            anthropicCountTokens('hi') +
            1600 +
            Math.ceil((requestBody.messages[0].content[2].source.data.length * 0.75) / 4) +
            anthropicCountTokens('MyTool') +
            anthropicCountTokens(JSON.stringify({ a: 1 })) +
            anthropicCountTokens('ok') +
            anthropicCountTokens('t') +
            anthropicCountTokens('d') +
            anthropicCountTokens(JSON.stringify({ type: 'object' }));

        expect(result).toEqual({ input_tokens: expected });
    });

    test('tool_use output should be gated by ORCHIDS_EMIT_TOOL_USE', async () => {
        class MockOrchidsService extends OrchidsApiService {
            async *generateContentStream() {
                yield { type: 'message_start', message: { id: 'msg_1', type: 'message', role: 'assistant', model: 'm', usage: { input_tokens: 0, output_tokens: 0 }, content: [] } };
                yield { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', id: 'toolu_1', name: 'X', input: {} } };
                yield { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"a":1}' } };
                yield { type: 'content_block_stop', index: 0 };
                yield { type: 'message_delta', delta: { stop_reason: 'tool_use', stop_sequence: null }, usage: { input_tokens: 0, output_tokens: 0 } };
                yield { type: 'message_stop' };
            }
        }

        const enabled = new MockOrchidsService({ ORCHIDS_EMIT_TOOL_USE: true });
        enabled.isInitialized = true;
        const enabledResp = await enabled.generateContent('m', {});
        expect(enabledResp.stop_reason).toBe('tool_use');
        expect(enabledResp.content).toEqual([{ type: 'tool_use', id: 'toolu_1', name: 'X', input: { a: 1 } }]);

        const disabled = new MockOrchidsService({ ORCHIDS_EMIT_TOOL_USE: false });
        disabled.isInitialized = true;
        const disabledResp = await disabled.generateContent('m', {});
        expect(disabledResp.stop_reason).toBe('end_turn');
        expect(disabledResp.content).toEqual([]);
    });

    test('multimodal blocks should produce placeholders and extract attachmentUrls', () => {
        const service = new OrchidsApiService({});

        const messages = [
            {
                role: 'user',
                content: [
                    { type: 'image', source: { type: 'url', url: 'https://example.com/a.png', media_type: 'image/png' } },
                    { type: 'document', source: { type: 'url', url: 'https://example.com/a.pdf' } },
                ],
            },
        ];

        const extracted = service._extractUserMessage(messages);
        expect(extracted.text).toContain('[Image');
        expect(extracted.text).toContain('[Document');
        expect(service._extractAttachmentUrls(messages)).toEqual(['https://example.com/a.png', 'https://example.com/a.pdf']);
    });

    test('tool name should map back to client-defined tool name', () => {
        const service = new OrchidsApiService({});
        const clientToolIndex = service._buildClientToolIndex([
            { name: 'functions.Read', input_schema: { type: 'object', properties: { file_path: { type: 'string' } } } },
            { name: 'Grep', input_schema: { type: 'object', properties: { pattern: { type: 'string' } } } },
        ]);

        expect(service._mapToolNameToClient('Read', { file_path: 'x.txt' }, clientToolIndex)).toBe('functions.Read');
        expect(service._mapToolNameToClient('ripgrep', null, clientToolIndex)).toBe('Grep');
    });
});
