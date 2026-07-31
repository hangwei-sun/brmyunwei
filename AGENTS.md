# Prototype Instructions

Run the local server yourself and open the preview in the in-app browser. Do not give the user server-start instructions when you can run it.

Before making substantial visual changes, use the Product Design plugin's `get-context` skill when the visual source is unclear or no longer matches the current goal. When the user gives durable prototype-specific design feedback, preferences, or decisions, record them in `AGENTS.md`.

When implementing from a selected generated mock, treat that image as the source of truth for layout, component anatomy, density, spacing, color, typography, visible content, and hierarchy.

## Current Product Brief

- Reference truth: `D:\code\yunwei\ui-designs\`.
- Product: a dense, desktop-first Windows data-center operations console.
- Required first-release flows: assets, real-time status, incident acknowledgement/silencing, rule inheritance, notification policies, Tencent Cloud SMS status, failover, and account roles.
- Visual language: dark navy sidebar, compact white data surfaces, blue primary actions, and restrained semantic green/orange/red status color.
- HA interaction: the top-bar dual-node entry opens a compact status modal; its node switch changes the browser's management endpoint only. Active/passive role changes remain fenced deployment operations, never a direct UI state mutation.
