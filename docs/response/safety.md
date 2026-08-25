# Response Safety & Defensive Principles

## Prohibited Patterns
The response engine enforces strict security constraints:
1. **No Unrestricted System Calls**: No `subprocess.Popen`, `os.system`, or shell invocation.
2. **No Arbitrary Code Interpretation**: No `eval()`, `exec()`, or dynamic AST generation.
3. **No Unsanitized SQL**: No raw SQL concatenation.
4. **Safe Simulation Adapters**: All containment actions default to simulation mode unless explicitly approved and configured.
