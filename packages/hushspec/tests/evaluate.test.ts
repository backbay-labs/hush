import { describe, expect, it } from 'vitest';
import { evaluate, parseOrThrow, type HushSpec } from '../src/index.js';

describe('evaluate', () => {
  it('preserves base tool blocks when an origin profile adds its own tool rules', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      name: 'origin-tool-access',
      rules: {
        tool_access: {
          enabled: true,
          block: ['dangerous_tool'],
          default: 'allow',
        },
      },
      extensions: {
        origins: {
          default_behavior: 'minimal_profile',
          profiles: [
            {
              id: 'slack-prod',
              match: { provider: 'slack' },
              tool_access: {
                enabled: true,
                allow: ['dangerous_tool'],
                default: 'allow',
              },
            },
          ],
        },
      },
    };

    const result = evaluate(spec, {
      type: 'tool_call',
      target: 'dangerous_tool',
      origin: { provider: 'slack' },
    });

    expect(result.decision).toBe('deny');
    expect(result.matched_rule).toBe('rules.tool_access.block');
  });

  it('preserves base egress restrictions when an origin profile adds its own egress rules', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      name: 'origin-egress',
      rules: {
        egress: {
          enabled: true,
          block: ['evil.example.com'],
          default: 'allow',
        },
      },
      extensions: {
        origins: {
          default_behavior: 'minimal_profile',
          profiles: [
            {
              id: 'public-room',
              match: { provider: 'slack' },
              egress: {
                enabled: true,
                allow: ['evil.example.com'],
                default: 'allow',
              },
            },
          ],
        },
      },
    };

    const result = evaluate(spec, {
      type: 'egress',
      target: 'evil.example.com',
      origin: { provider: 'slack' },
    });

    expect(result.decision).toBe('deny');
    expect(result.matched_rule).toBe('rules.egress.block');
  });

  it('continues to path allowlist checks after a forbidden-path exception', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      name: 'path-guards',
      rules: {
        forbidden_paths: {
          enabled: true,
          patterns: ['/secret/**'],
          exceptions: ['/secret/public/**'],
        },
        path_allowlist: {
          enabled: true,
          read: ['/workspace/**'],
        },
      },
    };

    const result = evaluate(spec, {
      type: 'file_read',
      target: '/secret/public/readme.txt',
    });

    expect(result.decision).toBe('deny');
    expect(result.matched_rule).toBe('rules.path_allowlist');
  });

  it('denies input injection types that are not explicitly allowed', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      name: 'input-injection',
      rules: {
        input_injection: {
          enabled: true,
          allowed_types: ['clipboard'],
        },
      },
    };

    const result = evaluate(spec, {
      type: 'input_inject',
      target: 'keystroke',
    });

    expect(result.decision).toBe('deny');
    expect(result.matched_rule).toBe('rules.input_injection.allowed_types');
  });

  it('treats input injection as disabled unless enabled is true', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      name: 'input-injection-default-disabled',
      rules: {
        input_injection: {},
      },
    };

    const result = evaluate(spec, {
      type: 'input_inject',
      target: 'keystroke',
    });

    expect(result.decision).toBe('allow');
    expect(result.matched_rule).toBeUndefined();
  });

  it('applies remote desktop channel blocks during computer-use evaluation', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      name: 'remote-desktop-channels',
      rules: {
        computer_use: {
          enabled: true,
          mode: 'observe',
          allowed_actions: [],
        },
        remote_desktop_channels: {
          enabled: true,
          clipboard: false,
          file_transfer: true,
          audio: true,
          drive_mapping: true,
        },
      },
    };

    const result = evaluate(spec, {
      type: 'computer_use',
      target: 'remote.clipboard',
    });

    expect(result.decision).toBe('deny');
    expect(result.matched_rule).toBe('rules.remote_desktop_channels.clipboard');
  });

  it('treats computer use as disabled unless enabled is true', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      name: 'computer-use-default-disabled',
      rules: {
        computer_use: {},
      },
    };

    const result = evaluate(spec, {
      type: 'computer_use',
      target: 'remote.session.connect',
    });

    expect(result.decision).toBe('allow');
    expect(result.matched_rule).toBeUndefined();
  });

  it('treats remote desktop channels as disabled unless enabled is true', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      name: 'remote-desktop-default-disabled',
      rules: {
        remote_desktop_channels: {},
      },
    };

    const result = evaluate(spec, {
      type: 'computer_use',
      target: 'remote.clipboard',
    });

    expect(result.decision).toBe('allow');
    expect(result.matched_rule).toBeUndefined();
  });

  it('defaults remote audio to allow when the channel rule is enabled', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      name: 'remote-audio-default-allow',
      rules: {
        remote_desktop_channels: {
          enabled: true,
        },
      },
    };

    const result = evaluate(spec, {
      type: 'computer_use',
      target: 'remote.audio',
    });

    expect(result.decision).toBe('allow');
    expect(result.matched_rule).toBe('rules.remote_desktop_channels.audio');
  });

  it('enforces RE2-style inline flags at runtime', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
rules:
  shell_commands:
    enabled: true
    forbidden_patterns:
      - "(?i)rm\\\\s+-rf\\\\s+/"
`);

    const result = evaluate(spec, {
      type: 'shell_command',
      target: 'RM -RF /tmp/demo',
    });

    expect(result.decision).toBe('deny');
    expect(result.matched_rule).toBe('rules.shell_commands.forbidden_patterns[0]');
  });

  it('fails closed when a runtime-only regex is outside the RE2 subset', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      rules: {
        shell_commands: {
          enabled: true,
          forbidden_patterns: ['(?<=sudo)rm\\s+-rf'],
        },
      },
    };

    const result = evaluate(spec, {
      type: 'shell_command',
      target: 'sudo rm -rf /tmp/demo',
    });

    expect(result.decision).toBe('deny');
    expect(result.matched_rule).toBe('rules.shell_commands.forbidden_patterns[0]');
    expect(result.reason).toContain('RE2 subset');
  });
});
