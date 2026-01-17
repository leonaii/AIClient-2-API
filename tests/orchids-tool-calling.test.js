import { OrchidsApiService } from '../src/providers/claude/claude-orchids.js';

describe('OrchidsApiService tool calling bridge', () => {
    test('tool_result should be included in next Orchids request payload', async () => {
        const service = new OrchidsApiService({ ORCHIDS_CREDS_FILE_PATH: 'dummy' });

        const claudeRequest = {
            model: 'claude-sonnet-4-5',
            messages: [
                {
                    role: 'user',
                    content: [{ type: 'text', text: 'List files.' }],
                },
                {
                    role: 'assistant',
                    content: [
                        {
                            type: 'tool_use',
                            id: 'toolu_1',
                            name: 'LS',
                            input: { path: '/' },
                        },
                    ],
                },
                {
                    role: 'user',
                    content: [
                        {
                            type: 'tool_result',
                            tool_use_id: 'toolu_1',
                            content: 'a.txt\nb.txt\n',
                        },
                    ],
                },
            ],
        };

        const orchidsRequest = await service._convertToOrchidsRequest('claude-sonnet-4-5', claudeRequest);

        expect(orchidsRequest.type).toBe('user_request');
        expect(Array.isArray(orchidsRequest.data?.toolResults)).toBe(true);
        expect(orchidsRequest.data.toolResults[0]).toMatchObject({
            toolUseId: 'toolu_1',
            status: 'success',
        });
        expect(orchidsRequest.data.toolResults[0].content.text).toContain('a.txt');
        expect(orchidsRequest.data?.chatHistory?.length).toBe(2);
        expect(orchidsRequest.data.chatHistory[1].role).toBe('assistant');
        expect(orchidsRequest.data.chatHistory[1].content).toContain('Used tool: LS');
    });

    test('fs_operation conversion should emit full JSON tool args for streaming conversion', () => {
        const service = new OrchidsApiService({ ORCHIDS_CREDS_FILE_PATH: 'dummy' });

        const events = service._convertFsOperationToToolUse(
            { id: 'op1', operation: 'read', path: 'a.txt' },
            0
        );

        expect(Array.isArray(events)).toBe(true);
        expect(events.length).toBeGreaterThanOrEqual(2);
        expect(events[0].type).toBe('content_block_start');
        expect(events[1].type).toBe('content_block_delta');
        expect(events[1].delta.type).toBe('input_json_delta');
        expect(events[1].delta.partial_json).toBe(JSON.stringify({ file_path: 'a.txt' }));
        expect(() => JSON.parse(events[1].delta.partial_json)).not.toThrow();
    });
});
