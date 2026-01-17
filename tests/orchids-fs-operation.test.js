import os from 'os';
import * as path from 'path';
import { promises as fs } from 'fs';
import { OrchidsApiService } from '../src/providers/claude/claude-orchids.js';

const WS_OPEN = 1;

describe('OrchidsApiService fs_operation executor', () => {
    test('write/read/delete should work with relative paths', async () => {
        const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'orchids-fs-'));
        const service = new OrchidsApiService({ ORCHIDS_LOCAL_WORKDIR: tmpDir });
        const sent = [];
        const ws = { readyState: WS_OPEN, send: (payload) => sent.push(JSON.parse(payload)) };

        await service._handleFsOperation(ws, { type: 'fs_operation', id: 'op1', operation: 'write', path: 'a.txt', content: 'hello' }, tmpDir);
        expect(sent[sent.length - 1]).toMatchObject({ type: 'fs_operation_response', id: 'op1', success: true });

        await service._handleFsOperation(ws, { type: 'fs_operation', id: 'op2', operation: 'read', path: 'a.txt' }, tmpDir);
        expect(sent[sent.length - 1]).toMatchObject({ type: 'fs_operation_response', id: 'op2', success: true, data: 'hello' });

        await service._handleFsOperation(ws, { type: 'fs_operation', id: 'op3', operation: 'delete', path: 'a.txt' }, tmpDir);
        expect(sent[sent.length - 1]).toMatchObject({ type: 'fs_operation_response', id: 'op3', success: true });

        await expect(fs.stat(path.join(tmpDir, 'a.txt'))).rejects.toThrow();
    });

    test('glob should match ** patterns from root', async () => {
        const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'orchids-glob-'));
        await fs.mkdir(path.join(tmpDir, 'sub'), { recursive: true });
        await fs.writeFile(path.join(tmpDir, 'a.txt'), 'a', 'utf8');
        await fs.writeFile(path.join(tmpDir, 'sub', 'b.txt'), 'b', 'utf8');

        const service = new OrchidsApiService({ ORCHIDS_LOCAL_WORKDIR: tmpDir });
        const sent = [];
        const ws = { readyState: WS_OPEN, send: (payload) => sent.push(JSON.parse(payload)) };

        await service._handleFsOperation(
            ws,
            { type: 'fs_operation', id: 'op1', operation: 'glob', globParameters: { path: tmpDir, pattern: '**/*.txt', maxResults: 10 } },
            tmpDir
        );

        const last = sent[sent.length - 1];
        expect(last.success).toBe(true);
        expect(last.data).toEqual(expect.arrayContaining([path.join(tmpDir, 'a.txt'), path.join(tmpDir, 'sub', 'b.txt')]));
    });

    test('ripgrep should return rg-like output', async () => {
        const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'orchids-rg-'));
        await fs.writeFile(path.join(tmpDir, 'a.txt'), 'hello\nworld\nhello again\n', 'utf8');

        const service = new OrchidsApiService({ ORCHIDS_LOCAL_WORKDIR: tmpDir });
        const sent = [];
        const ws = { readyState: WS_OPEN, send: (payload) => sent.push(JSON.parse(payload)) };

        await service._handleFsOperation(
            ws,
            {
                type: 'fs_operation',
                id: 'op1',
                operation: 'ripgrep',
                ripgrepParameters: { query: 'hello', paths: [tmpDir], maxResults: 10, caseInsensitive: false, isRegex: false },
            },
            tmpDir
        );

        const last = sent[sent.length - 1];
        expect(last.success).toBe(true);
        expect(last.data).toContain(path.join(tmpDir, 'a.txt'));
        expect(last.data).toContain(':1:1:hello');
    });

    test('run_command should be blocked by default', async () => {
        const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'orchids-cmd-'));
        const service = new OrchidsApiService({ ORCHIDS_LOCAL_WORKDIR: tmpDir });
        const sent = [];
        const ws = { readyState: WS_OPEN, send: (payload) => sent.push(JSON.parse(payload)) };

        await service._handleFsOperation(
            ws,
            { type: 'fs_operation', id: 'op1', operation: 'run_command', command: 'node -e \"console.log(123)\"' },
            tmpDir
        );

        const last = sent[sent.length - 1];
        expect(last.success).toBe(false);
        expect(last.error).toContain('disabled');
    });
});

