# 3-minute demo script

| Time | Do | Say |
|------|----|-----|
| 0:00 | Show dashboard | "AI agents can be manipulated through prompt injection. PromptGuard is a firewall that sits between users and the agent." |
| 0:20 | Click **Safe question** > Analyze | "Safe prompts pass through and reach the assistant. We don't block everything." |
| 0:50 | Click **Instruction override** > Analyze | "Critical risk, blocked before the LLM ever sees it. Here is why." (point at reasons) |
| 1:20 | Click **Jailbreak**, then **Prompt extraction** | "Not just one phrase: different attack families are detected." |
| 1:45 | Click **Obfuscated**, then **Encoded** | "Leetspeak and Base64 are unmasked first, then analysed." (point at 'Unmasked text') |
| 2:10 | Click **Mixed request** | "Partly suspicious? We sanitize: remove the malicious part, keep the legitimate question." |
| 2:30 | Click agent cards | "Five agents: detect, verify, score risk, decide policy, explain." |
| 2:50 | Point to chart + history | "Every decision is logged in Supabase for audit and analytics." |
| 3:10 | Close | "We're not replacing AI agents. We're the security layer that lets enterprises use them safely." |

Tip: click **Load sample traffic into the dashboard** before recording so the chart is not empty.
